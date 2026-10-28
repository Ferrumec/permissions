use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use uuid::Uuid;
use viewset::Entity;

#[derive(FromRow, Deserialize, Serialize, Clone, Entity)]
#[entity(table = "grants", create = "Authority", update = "UpdateAbsolute")]
pub struct Absolute {
    #[entity(skip_update, skip_create)]
    pub id: Uuid,
    #[entity(skip_update, filterable)]
    pub sub: Uuid,
    /// Represent u128 permission bit map, represented as str since some db do not support u128
    pub role: Uuid,
    #[entity(skip_update, filterable)]
    pub namespace: Uuid,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Authority {
    pub sub: Uuid,
    pub namespace: Uuid,
    pub role: Uuid,
}

impl From<Absolute> for Authority {
    fn from(value: Absolute) -> Authority {
        let Absolute {
            sub,
            namespace,
            role,
            ..
        } = value;
        Authority {
            sub,
            namespace,
            role,
        }
    }
}

pub trait Role {
    fn role(&self) -> u128;
}

impl Role for Authority {
    fn role(&self) -> u128 {
        self.role.as_u128()
    }
}

impl AuthzControls for Authority {}

impl AuthzControls for Absolute {}

impl Role for Absolute {
    fn role(&self) -> u128 {
        self.role.as_u128()
    }
}

pub trait AuthzControls: Role {
    fn grant(&self, perm_value: Uuid) -> UpdateAbsolute {
        let current = self.role();
        let new = current | perm_value.as_u128();
        UpdateAbsolute {
            role: Some(Uuid::from_u128(new)),
        }
    }

    fn deny(&self, perm_value: Uuid) -> UpdateAbsolute {
        let current = self.role();
        let new = current & !perm_value.as_u128();
        UpdateAbsolute {
            role: Some(Uuid::from_u128(new)),
        }
    }

    fn has(&self, value: Uuid) -> bool {
        let value = value.as_u128();
        self.role() & value == value
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UpdateAbsolute {
    pub role: Option<Uuid>,
}
