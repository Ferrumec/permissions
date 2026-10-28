use super::permission::PermissionSet;
use crate::repo::Role;
use crate::{Absolute, Authority};
use actix_web::HttpMessage;
use actix_web::body::{BoxBody, MessageBody};
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::{
    Error, FromRequest, HttpRequest, HttpResponse, dev::Payload, error::ErrorInternalServerError,
};
use futures_util::future::LocalBoxFuture;
use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use uuid::Uuid;
use viewset::Repository;
use viewset::DefaultRepo;

#[derive(Clone)]
pub struct Permissions {
    permission_set: Arc<PermissionSet>,
    store: Arc<DefaultRepo<Absolute>>,
}


impl FromRequest for Authority {
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        // Prefer the Filters already constructed by middleware.
        if let Some(filters) = req.extensions().get::<Authority>() {
            return Box::pin(ready(Ok(filters.clone())));
        }
        tracing::error!("Permission middleware not wrapped for {}", req.path());
        Box::pin(ready(Err(ErrorInternalServerError("Configuration Error"))))
    }
}

impl Permissions {
    pub fn new(permission_set: PermissionSet, infra: impl ferrumec::Infra) -> Self {
        let store = DefaultRepo::new(infra.database(), infra.cache_factory());
        Self {
            permission_set: Arc::new(permission_set),
            store: store.into(),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for Permissions
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = PermissionsMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(PermissionsMiddleware {
            service: Rc::new(service),
            store: Arc::clone(&self.store),
            permission_set: Arc::clone(&self.permission_set),
        }))
    }
}

pub struct PermissionsMiddleware<S> {
    service: Rc<S>,
    permission_set: Arc<PermissionSet>,
    store: Arc<DefaultRepo<Absolute>>,
}

impl<S, B> Service<ServiceRequest> for PermissionsMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;

    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let method = req.method().clone();
        let path = req.path().to_string();

        let permission = self.permission_set.find(&method, &path);

        // No permission configured: default allow.
        let Some(perm) = permission else {
            let service = Rc::clone(&self.service);

            return Box::pin(async move {
                let res = service.call(req).await?;
                Ok(res.map_into_boxed_body())
            });
        };

        // IMPORTANT:
        // `perm` is borrowed from `self.permission_set`.
        // Copy the value we need so the async future doesn't borrow `self`.
        let bit_id = perm.bit_id;

        let Some(cookie) = req.cookie("permission") else {
            return Box::pin(async move {
                Ok(req.into_response(HttpResponse::Unauthorized().finish()))
            });
        };

        let id = match Uuid::parse_str(cookie.value()){
            Ok(id)=>id,
            Err(e)=>{
                return Box::pin(async move {
                tracing::error!("error in parsing permission token: {e}, token={}",cookie.value());
                Ok(req.into_response(HttpResponse::InternalServerError().finish()))
            });
            }
            
        };

        let store = Arc::clone(&self.store);
        let service = Rc::clone(&self.service);

        Box::pin(async move {
            let authority: Authority = match store.retrieve(&id).await {
                Ok(authority) => authority.into(),

                Err(e) => {
                    tracing::error!("failed to retrieve grant from database: {e}");
                    return Ok(req.into_response(HttpResponse::InternalServerError().finish()));
                }
            };

            req.extensions_mut().insert(authority.clone());

            let role = authority.role();

            let bit_mask = 1u128 << bit_id;

            if role & bit_mask == 0 {
                return Ok(req.into_response(HttpResponse::Forbidden().finish()));
            }

            let res = service.call(req).await?;

            Ok(res.map_into_boxed_body())
        })
    }
}
