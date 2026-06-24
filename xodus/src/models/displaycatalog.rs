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
    pub historical_best_availabilities: Vec<HistoricalBestAvailability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Sku {
    pub last_modified_date: String,
    pub localized_properties: Vec<SkuLocalizedProperty>,
    pub market_properties: Vec<SkuMarketProperty>,
    pub product_id: String,
    pub properties: SkuProperties,
    pub sku_a_schema: String,
    pub sku_b_schema: String,
    pub sku_id: String,
    pub sku_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recurrence_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_policy_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SkuLocalizedProperty {
    pub contributors: Vec<String>,
    pub features: Vec<String>,
    pub minimum_notes: String,
    pub recommended_notes: String,
    pub release_notes: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_platform_properties: Option<String>,
    pub sku_description: String,
    pub sku_title: String,
    pub sku_button_title: String,
    pub delivery_date_overlay: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_resources: Option<String>,
    pub legal_text: LegalText,
    pub language: String,
    pub markets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LegalText {
    pub additional_license_terms: String,
    pub copyright: String,
    pub copyright_uri: String,
    pub privacy_policy: String,
    pub privacy_policy_uri: String,
    pub tou: String,
    pub tou_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SkuMarketProperty {
    pub first_available_date: String,
    pub supported_languages: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_ids: Option<Vec<String>>,
    #[serde(rename = "PIFilter", skip_serializing_if = "Option::is_none")]
    pub pi_filter: Option<String>,
    pub markets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SkuProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub early_adopter_enrollment_url: Option<String>,
    pub fulfillment_data: Option<FulfillmentData>,
    pub fulfillment_type: Option<String>,
    pub fulfillment_plugin_id: Option<String>,
    #[serde(default)]
    pub has_third_party_i_a_ps: bool,
    pub last_update_date: String,
    pub hardware_properties: Option<HardwareProperties>,
    pub hardware_requirements: Vec<String>,
    pub hardware_warning_list: Vec<String>,
    pub installation_terms: String,
    pub packages: Vec<Package>,
    pub version_string: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sku_display_group_ids: Option<Vec<String>>,
    #[serde(default)]
    pub xbox_xpa: bool,
    // pub bundled_skus: Vec<String>,
    pub is_repurchasable: bool,
    // pub sku_display_rank: Vec<SkuDisplayRank>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_physical_store_inventory: Option<String>,
    #[serde(default)]
    pub visible_to_b2b_service_ids: Vec<String>,
    pub additional_identifiers: Vec<String>,
    pub is_trial: bool,
    pub is_pre_order: bool,
    pub is_bundle: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FulfillmentData {
    pub product_id: String,
    pub wu_bundle_id: String,
    pub wu_category_id: String,
    pub package_family_name: String,
    pub sku_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_features: Option<PackageFeatures>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PackageFeatures {
    pub supports_intelligent_delivery: bool,
    pub supports_install_features: bool,
    pub supports_install_recipes: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HardwareProperties {
    pub minimum_hardware: Vec<String>,
    pub recommended_hardware: Vec<String>,
    pub minimum_processor: Option<String>,
    pub recommended_processor: Option<String>,
    pub minimum_graphics: Option<String>,
    pub recommended_graphics: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Package {
    pub applications: Vec<Application>,
    pub architectures: Vec<String>,
    pub capabilities: Vec<String>,
    pub device_capabilities: Vec<String>,
    pub experience_ids: Vec<String>,
    pub framework_dependencies: Vec<FrameworkDependency>,
    pub hardware_dependencies: Vec<String>,
    pub hardware_requirements: Vec<String>,
    pub hash: String,
    pub hash_algorithm: String,
    pub is_streaming_app: bool,
    pub languages: Vec<String>,
    pub max_download_size_in_bytes: i64,
    pub max_install_size_in_bytes: Option<i64>,
    pub package_format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub main_package_family_name_for_dlc: Option<String>,
    pub package_full_name: String,
    pub package_id: String,
    #[serde(default)]
    pub content_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub package_rank: i32,
    pub package_uri: String,
    pub platform_dependencies: Vec<PlatformDependency>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_dependency_xml_blob: Option<String>,
    pub resource_id: Option<String>,
    pub version: String,
    #[serde(default)]
    pub package_download_uris: Option<Vec<PackageDownloadUri>>,
    pub driver_dependencies: Vec<String>,
    pub fulfillment_data: PackageFulfillmentData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Application {
    pub application_id: String,
    pub declaration_order: i32,
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FrameworkDependency {
    pub max_tested: i64,
    pub min_version: i64,
    pub package_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PlatformDependency {
    pub max_tested: i64,
    pub min_version: i64,
    pub platform_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PackageDownloadUri {
    pub rank: i32,
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PackageFulfillmentData {
    pub product_id: String,
    pub wu_bundle_id: String,
    pub wu_category_id: String,
    pub package_family_name: String,
    pub sku_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_content_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_features: Option<PackageFeatures>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Availability {
    pub actions: Vec<String>,
    pub availability_a_schema: String,
    pub availability_b_schema: String,
    pub availability_id: String,
    pub conditions: Conditions,
    pub last_modified_date: String,
    pub markets: Vec<String>,
    pub order_management_data: OrderManagementData,
    pub properties: serde_json::Value,
    pub sku_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affirmation_id: Option<String>,
    pub display_rank: i32,
    #[serde(default)]
    pub remediation_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub licensing_data: Option<LicensingData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Conditions {
    pub client_conditions: ClientConditions,
    pub end_date: String,
    pub resource_set_ids: Vec<String>,
    pub start_date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eligibility_predicate_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_catalog_version: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ClientConditions {
    pub allowed_platforms: Vec<AllowedPlatform>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AllowedPlatform {
    pub max_version: i64,
    pub min_version: i64,
    pub platform_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct OrderManagementData {
    pub granted_entitlement_keys: Vec<String>,
    #[serde(rename = "PIFilter", skip_serializing_if = "Option::is_none")]
    pub pi_filter: Option<PIFilter>,
    pub price: Price,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PIFilter {
    pub exclusion_properties: Vec<String>,
    pub inclusion_properties: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Price {
    pub currency_code: String,
    #[serde(default)]
    pub is_pi_required: bool,
    pub list_price: f64,
    #[serde(rename = "MSRP")]
    pub msrp: f64,
    pub tax_type: String,
    pub wholesale_currency_code: String,
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
    pub licensing_key_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_order_release_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HistoricalBestAvailability {
    pub actions: Vec<String>,
    pub availability_a_schema: String,
    pub availability_b_schema: String,
    pub availability_id: String,
    pub conditions: Conditions,
    pub last_modified_date: String,
    pub markets: Vec<String>,
    pub order_management_data: OrderManagementData,
    pub properties: serde_json::Value,
    pub sku_id: String,
    pub display_rank: i32,
    pub product_a_schema: String,
}
