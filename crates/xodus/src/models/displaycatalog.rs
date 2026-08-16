use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DisplayCatalogProductsResponse {
    pub product: Product,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Product {
    pub display_sku_availabilities: Vec<DisplaySkuAvailability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DisplaySkuAvailability {
    pub sku: Sku,
    pub availabilities: Vec<Availability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Sku {
    pub properties: SkuProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SkuProperties {
    pub packages: Vec<Package>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Package {
    #[serde(default)]
    pub content_id: Option<String>,
    pub platform_dependencies: Vec<PlatformDependency>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PlatformDependency {
    pub platform_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Availability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub licensing_data: Option<LicensingData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LicensingData {
    pub satisfying_entitlement_keys: Vec<SatisfyingEntitlementKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SatisfyingEntitlementKey {
    pub entitlement_keys: Vec<String>,
}
