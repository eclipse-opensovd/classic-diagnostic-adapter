use hashbrown::HashMap;

pub struct Fault {
    ///Fault code in the native representation of the entity.
    pub code: String,
    // Defines the scope
    // The capability description defines which scopes are supported
    pub scope: Option<String>,
    /// Display representation of the fault code
    pub display_code: Option<String>,
    /// Name / description of the fault code
    pub fault_name: String,
    /// Identifier for translating the name
    pub fault_translation_id: Option<String>,
    /// Severity defines the impact of the fault on the system
    /// For classic ECUs this is the level from the ODX,
    /// on HPCPs SOVD recommends 1 = FATAL, 2 = ERROR, 3 = WARNING, 4 = INFO
    pub severity: Option<u32>,
    /// Detailed status information as key value pairs
    /// Only present if the fault provides this information
    pub status: Option<HashMap<String, serde_json::Value>>,
    /// Detailed symptom / failure mode information
    /// Only present if the fault provides this information
    pub symptom: Option<String>,
    /// Translation ID for the symptom
    /// Only present if the fault provides this information
    pub symptom_translation_id: Option<String>,
    /// OpenAPI schema for the fault element.
    /// Only present if the query parameter ?include_schema=true was used
    pub schema: Option<String>,
}
