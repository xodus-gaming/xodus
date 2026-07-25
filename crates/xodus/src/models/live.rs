use serde::{Deserialize, Serialize};

use crate::models::soap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DAProperty {
    #[serde(rename = "sDAToken")]
    pub da_token: String,
    #[serde(rename = "sDASessionKey")]
    pub da_session_key: String,
    #[serde(rename = "sDAStartTime")]
    pub da_start_time: String,
    #[serde(rename = "sDAExpires")]
    pub da_expires: String,
    #[serde(rename = "sSTSInlineFlowToken")]
    pub sts_inline_flow_token: String,
    #[serde(rename = "sSigninName")]
    pub username: String,
    #[serde(rename = "K")]
    pub puid: String,
}

#[derive(Deserialize, Debug)]
pub struct HostBridgeMessage {
    #[serde(rename = "type")]
    pub message_type: Option<String>,
    pub value: Option<HostBridgeValue>,
}

#[derive(Deserialize, Debug)]
pub struct HostBridgeValue {
    pub name: Option<String>,
    pub context: Option<String>,
}

impl HostBridgeMessage {
    pub fn get_context_invoke(&self) -> Option<&str> {
        let value = self.value.as_ref()?;
        if self.message_type.as_deref() == Some("invoke")
            && value.name.as_deref() == Some("CloudExperienceHost.getContext")
        {
            value.context.as_deref()
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub enum ExchangeUserTokenOutcome {
    Issued(soap::BodyContent),
    Fault(Option<soap::PP>),
}
