//! Core data types: Match, PatternDef, and pattern metadata.

use serde::{Deserialize, Serialize};

/// A single sensitive-data match found by the scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    /// The matched text from the input.
    pub text: String,
    /// Top-level pattern category (e.g., "Credit Card Numbers").
    pub category: String,
    /// Specific pattern name (e.g., "Visa").
    pub sub_category: String,
    /// Whether contextual keywords were found nearby.
    pub has_context: bool,
    /// Confidence score from 0.0 to 1.0.
    pub confidence: f64,
    /// (start, end) byte offsets in the input text.
    pub span: (usize, usize),
    /// Whether this pattern requires context to be reliable.
    pub context_required: bool,
}

impl Match {
    /// Create a new Match.
    pub fn new(
        text: String,
        category: String,
        sub_category: String,
        has_context: bool,
        confidence: f64,
        span: (usize, usize),
        context_required: bool,
    ) -> Self {
        Self {
            text,
            category,
            sub_category,
            has_context,
            confidence,
            span,
            context_required,
        }
    }

    /// Return a redacted version of the matched text.
    /// Shows first 3 and last 3 characters for matches longer than 8 chars.
    pub fn redacted_text(&self) -> String {
        if self.text.len() <= 8 {
            "*".repeat(self.text.len())
        } else {
            let first: String = self.text.chars().take(3).collect();
            let last: String = self.text.chars().rev().take(3).collect::<Vec<_>>().into_iter().rev().collect();
            let middle_len = self.text.chars().count().saturating_sub(6);
            format!("{}{}{}", first, "*".repeat(middle_len), last)
        }
    }

    /// Convert to a JSON-serializable map.
    pub fn to_dict(&self, redact: bool) -> serde_json::Value {
        let mut val = serde_json::to_value(self).unwrap_or_default();
        if redact {
            if let Some(obj) = val.as_object_mut() {
                obj.insert("text".into(), serde_json::Value::String(self.redacted_text()));
            }
        }
        val
    }
}

/// Definition of a DLP pattern used by the scanner.
#[derive(Debug, Clone)]
pub struct PatternDef {
    /// Top-level category name.
    pub category: &'static str,
    /// Specific pattern name within the category.
    pub sub_category: &'static str,
    /// The regex pattern string.
    pub regex: &'static str,
    /// Whether this pattern is case-insensitive.
    pub case_insensitive: bool,
    /// Base specificity score (0.0-1.0).
    pub specificity: f64,
    /// Whether context keywords are required for this pattern.
    pub context_required: bool,
}

/// Default specificity for patterns not explicitly scored.
pub const DEFAULT_SPECIFICITY: f64 = 0.40;

/// Get the specificity score for a sub_category.
pub fn pattern_specificity(sub_category: &str) -> f64 {
    match sub_category {
        // Credit Cards (Luhn-validated, highly specific)
        "Visa" | "MasterCard" | "Amex" | "Discover" | "JCB" | "Diners Club" | "UnionPay" => 0.90,
        "PAN" => 0.60,
        "Masked PAN" => 0.85,
        "Track 1 Data" | "Track 2 Data" => 0.95,
        "Card Expiry" => 0.30,

        // Banking
        "IBAN Generic" => 0.90,
        "SWIFT/BIC" => 0.85,
        "ABA Routing Number" => 0.55,
        "US Bank Account Number" => 0.20,
        "Canada Transit Number" => 0.40,
        "Fedwire IMAD" => 0.90,
        "CHIPS UID" => 0.50,
        "Wire Reference Number" | "SEPA Reference" => 0.50,
        "ACH Trace Number" => 0.55,
        "ACH Batch Number" => 0.20,
        "MICR Line" => 0.90,
        "Check Number" => 0.15,
        "Cashier Check Number" => 0.20,
        "CUSIP" => 0.70,
        "ISIN" => 0.75,
        "SEDOL" => 0.70,
        "FIGI" => 0.90,
        "LEI" => 0.80,
        "Ticker Symbol" => 0.80,
        "Loan Number" => 0.45,
        "MERS MIN" => 0.50,
        "Universal Loan Identifier" => 0.75,
        "LTV Ratio" => 0.40,
        "SAR Filing Number" | "CTR Number" | "FinCEN Report Number" => 0.30,
        "AML Case ID" => 0.60,
        "OFAC SDN Entry" => 0.15,
        "Compliance Case Number" => 0.55,
        "PIN Block" => 0.65,
        "HSM Key" => 0.55,
        "Encryption Key" => 0.50,
        "Account Balance" => 0.50,
        "Balance with Currency Code" => 0.55,
        "Income Amount" => 0.40,
        "DTI Ratio" => 0.45,
        "Internal Account Ref" => 0.50,
        "Teller ID" => 0.35,
        "Cardholder Name Pattern" => 0.10,

        // National IDs
        "USA SSN" => 0.55,
        "USA ITIN" => 0.60,
        "Canada SIN" => 0.55,
        "UK NIN" => 0.65,

        // Contact Info
        "Email Address" => 0.90,
        "E.164 Phone Number" => 0.70,
        "US Phone Number" => 0.50,
        "UK Phone Number" => 0.50,
        "IPv4 Address" => 0.60,
        "IPv6 Address" => 0.80,
        "MAC Address" => 0.80,

        // PII
        "Date of Birth" => 0.40,
        "Gender Marker" => 0.25,
        "GPS Coordinates" => 0.80,
        "GPS DMS" => 0.85,
        "Geohash" => 0.60,
        "US ZIP+4 Code" => 0.55,
        "UK Postcode" => 0.70,
        "Canada Postal Code" => 0.75,
        "Japan Postal Code" => 0.45,
        "Brazil CEP" => 0.45,
        "IMEI" | "IMEISV" => 0.55,
        "MEID" => 0.70,
        "ICCID" => 0.85,
        "IDFA/IDFV" => 0.85,
        "Health Plan ID" => 0.60,
        "DEA Number" => 0.55,
        "ICD-10 Code" => 0.50,
        "NDC Code" => 0.65,
        "Insurance Policy Number" => 0.50,
        "Insurance Claim Number" => 0.45,
        "Session ID" => 0.55,
        "Twitter Handle" => 0.60,
        "Hashtag" => 0.30,
        "EDU Email" => 0.90,
        "US Federal Case Number" => 0.80,
        "Court Docket Number" => 0.45,
        "Employee ID" => 0.35,
        "Work Permit Number" => 0.50,
        "Biometric Hash" => 0.70,
        "Biometric Template ID" => 0.75,
        "Parcel Number" => 0.60,
        "Title Deed Number" => 0.40,

        // Secrets
        "Bearer Token" => 0.80,
        "JWT Token" => 0.95,
        "Private Key" => 0.95,
        "Generic API Key" => 0.50,
        "Database Connection String" => 0.90,
        "AWS Access Key" => 0.95,
        "AWS Secret Key" => 0.90,
        "Google API Key" => 0.90,
        "GitHub Token (Classic)" | "GitHub Token (Fine-Grained)" | "GitHub OAuth Token" => 0.95,
        "NPM Token" | "PyPI Token" => 0.95,
        "Stripe Secret Key" => 0.95,
        "Stripe Publishable Key" => 0.85,
        "Slack Bot Token" | "Slack User Token" => 0.95,
        "Slack Webhook" => 0.90,
        "SendGrid API Key" => 0.95,
        "Twilio API Key" | "Mailgun API Key" => 0.90,

        // Cryptocurrency
        "Bitcoin Address (Legacy)" | "Bitcoin Address (Bech32)" | "Ethereum Address" | "Litecoin Address" | "Ripple Address" => 0.80,
        "Bitcoin Cash Address" => 0.75,
        "Monero Address" => 0.85,

        // Vehicles
        "VIN" => 0.70,

        // URLs
        "URL with Password" => 0.90,
        "URL with Token" => 0.75,

        // --- US State Driver's Licenses ---
        "Alabama DL" | "Alaska DL" | "Arizona DL" | "Arkansas DL" | "California DL"
        | "Colorado DL" | "Connecticut DL" | "DC DL" | "Delaware DL" | "Florida DL"
        | "Georgia DL" | "Hawaii DL" | "Idaho DL" | "Illinois DL" | "Indiana DL"
        | "Iowa DL" | "Kansas DL" | "Kentucky DL" | "Louisiana DL" | "Maine DL"
        | "Maryland DL" | "Massachusetts DL" | "Michigan DL" | "Minnesota DL"
        | "Mississippi DL" | "Missouri DL" | "Montana DL" | "Nebraska DL"
        | "Nevada DL" | "New Hampshire DL" | "New Jersey DL" | "New Mexico DL"
        | "New York DL" | "North Carolina DL" | "North Dakota DL" | "Ohio DL"
        | "Oklahoma DL" | "Oregon DL" | "Pennsylvania DL" | "Rhode Island DL"
        | "South Carolina DL" | "South Dakota DL" | "Tennessee DL" | "Texas DL"
        | "Utah DL" | "Vermont DL" | "Virginia DL" | "Washington DL"
        | "West Virginia DL" | "Wisconsin DL" | "Wyoming DL"
        | "Generic US DL" => 0.55,

        // --- Canadian Provincial Driver's Licenses ---
        "Alberta DL" | "British Columbia DL" | "Manitoba DL" | "New Brunswick DL"
        | "Newfoundland DL" | "Nova Scotia DL" | "NWT DL" | "Nunavut DL"
        | "Ontario DL" | "PEI DL" | "Quebec DL" | "Saskatchewan DL"
        | "Yukon DL" => 0.55,

        // --- Canadian Provincial Health Cards ---
        "Alberta HC" | "BC HC" | "Manitoba HC" | "New Brunswick HC"
        | "Newfoundland HC" | "Nova Scotia HC" | "Ontario HC" | "PEI HC"
        | "Quebec HC" | "Saskatchewan HC" => 0.55,

        // --- Canadian National IDs ---
        "Canada Passport" | "Canada PR Card" | "Canada NEXUS" => 0.80,
        "Canada BN" | "Canada Bank Code" => 0.70,

        // --- US National IDs ---
        "USA Passport" | "USA Passport Card" => 0.80,
        "USA EIN" => 0.70,
        "USA Routing Number" => 0.55,
        "US DoD ID" => 0.70,
        "US Known Traveler Number" => 0.70,
        "US MBI" => 0.70,
        "US NPI" | "NPI" => 0.70,
        "US DEA Number" => 0.55,

        // --- UK IDs ---
        "UK Passport" => 0.80,
        "UK DL" => 0.55,
        "UK Sort Code" => 0.50,
        "UK UTR" => 0.70,
        "British NHS" => 0.70,

        // --- Ireland ---
        "Ireland Passport" => 0.80,
        "Ireland PPS" => 0.70,
        "Ireland DL" => 0.55,
        "Ireland Eircode" => 0.50,

        // --- France ---
        "France Passport" => 0.80,
        "France CNI" => 0.70,
        "France NIR" => 0.70,
        "France DL" => 0.55,
        "France IBAN" => 0.90,

        // --- Germany ---
        "Germany Passport" => 0.80,
        "Germany ID" => 0.70,
        "Germany Tax ID" => 0.70,
        "Germany Social Insurance" => 0.70,
        "Germany DL" => 0.55,
        "Germany IBAN" => 0.90,

        // --- Italy ---
        "Italy Passport" => 0.80,
        "Italy Codice Fiscale" => 0.70,
        "Italy SSN" => 0.70,
        "Italy Partita IVA" => 0.70,
        "Italy DL" => 0.55,

        // --- Spain ---
        "Spain Passport" => 0.80,
        "Spain DNI" => 0.70,
        "Spain NIE" => 0.70,
        "Spain NSS" => 0.70,
        "Spain DL" => 0.55,

        // --- Portugal ---
        "Portugal Passport" => 0.80,
        "Portugal CC" => 0.70,
        "Portugal NIF" => 0.70,
        "Portugal NISS" => 0.70,

        // --- Netherlands ---
        "Netherlands Passport" => 0.80,
        "Netherlands BSN" => 0.70,
        "Netherlands DL" => 0.55,
        "Netherlands IBAN" => 0.90,

        // --- Belgium ---
        "Belgium Passport" => 0.80,
        "Belgium NRN" => 0.70,
        "Belgium VAT" => 0.70,
        "Belgium DL" => 0.55,

        // --- Austria ---
        "Austria Passport" => 0.80,
        "Austria ID Card" => 0.70,
        "Austria SVN" => 0.70,
        "Austria Tax Number" => 0.70,
        "Austria DL" => 0.55,

        // --- Switzerland ---
        "Switzerland Passport" => 0.80,
        "Switzerland AHV" => 0.70,
        "Switzerland UID" => 0.70,
        "Switzerland DL" => 0.55,

        // --- Liechtenstein ---
        "Liechtenstein Passport" => 0.80,
        "Liechtenstein PIN" => 0.70,

        // --- Luxembourg ---
        "Luxembourg Passport" => 0.80,
        "Luxembourg NIN" => 0.70,
        "Luxembourg DL" => 0.55,

        // --- Nordics ---
        "Denmark Passport" | "Finland Passport" | "Iceland Passport"
        | "Norway Passport" | "Sweden Passport" => 0.80,
        "Denmark CPR" | "Finland HETU" | "Iceland Kennitala"
        | "Norway FNR" | "Norway D-Number" | "Sweden PIN"
        | "Sweden Organisation Number" => 0.70,
        "Denmark DL" | "Finland DL" | "Norway DL" | "Sweden DL" => 0.55,

        // --- Baltics ---
        "Estonia Passport" | "Latvia Passport" | "Lithuania Passport" => 0.80,
        "Estonia Isikukood" | "Latvia Personas Kods" | "Lithuania Asmens Kodas" => 0.70,
        "Estonia DL" | "Latvia DL" | "Lithuania DL" => 0.55,

        // --- Eastern Europe ---
        "Poland Passport" | "Czech Passport" | "Slovakia Passport"
        | "Hungary Passport" | "Romania Passport" | "Bulgaria Passport"
        | "Croatia Passport" | "Slovenia Passport" => 0.80,
        "Poland PESEL" | "Poland NIP" | "Poland REGON" | "Poland ID Card" => 0.70,
        "Czech Birth Number" | "Czech ICO" => 0.70,
        "Slovakia Birth Number" => 0.70,
        "Hungary Personal ID" | "Hungary TAJ" | "Hungary Tax Number" => 0.70,
        "Romania CNP" | "Romania CIF" => 0.70,
        "Bulgaria EGN" | "Bulgaria LNC" | "Bulgaria ID Card" => 0.70,
        "Croatia OIB" | "Croatia ID Card" => 0.70,
        "Slovenia EMSO" | "Slovenia Tax Number" => 0.70,
        "Poland DL" | "Czech DL" | "Slovakia DL" | "Hungary DL"
        | "Romania DL" | "Croatia DL" | "Slovenia DL" => 0.55,

        // --- Greece ---
        "Greece Passport" => 0.80,
        "Greece AFM" | "Greece AMKA" | "Greece ID Card" => 0.70,
        "Greece DL" => 0.55,

        // --- Cyprus / Malta ---
        "Cyprus Passport" | "Malta Passport" => 0.80,
        "Cyprus ID Card" | "Cyprus TIN" => 0.70,
        "Malta ID Card" | "Malta TIN" => 0.70,

        // --- Turkey ---
        "Turkey Passport" => 0.80,
        "Turkey TC Kimlik" => 0.70,
        "Turkey Tax ID" => 0.70,
        "Turkey DL" => 0.55,

        // --- EU generic ---
        "EU VAT Generic" => 0.70,
        "EU ETD" => 0.80,

        // --- India ---
        "India Passport" => 0.80,
        "India Aadhaar" => 0.70,
        "India PAN" => 0.70,
        "India Voter ID" => 0.70,
        "India Ration Card" => 0.70,
        "India DL" => 0.55,

        // --- China ---
        "China Passport" => 0.80,
        "China Resident ID" => 0.70,

        // --- Japan ---
        "Japan Passport" => 0.80,
        "Japan My Number" => 0.70,
        "Japan DL" => 0.55,
        "Japan Health Insurance" => 0.70,
        "Japan Juminhyo Code" => 0.70,
        "Japan Residence Card" => 0.70,

        // --- South Korea ---
        "South Korea Passport" => 0.80,
        "South Korea RRN" => 0.70,
        "South Korea DL" => 0.55,

        // --- Southeast Asia ---
        "Singapore Passport" | "Malaysia Passport" | "Indonesia Passport"
        | "Philippines Passport" | "Thailand Passport" | "Vietnam Passport"
        | "Sri Lanka Passport" => 0.80,
        "Singapore NRIC" | "Singapore FIN" => 0.70,
        "Malaysia MyKad" => 0.70,
        "Indonesia NIK" | "Indonesia NPWP" => 0.70,
        "Philippines PhilSys" | "Philippines SSS" | "Philippines TIN"
        | "Philippines UMID" | "Philippines PhilHealth" => 0.70,
        "Thailand National ID" | "Thailand Tax ID" => 0.70,
        "Vietnam CCCD" | "Vietnam Tax Code" => 0.70,
        "Sri Lanka NIC New" | "Sri Lanka NIC Old" => 0.70,
        "Singapore DL" | "Thailand DL" => 0.55,

        // --- Hong Kong / Macau / Taiwan ---
        "Hong Kong ID" => 0.70,
        "Macau ID" => 0.70,
        "Taiwan National ID" => 0.70,

        // --- Bangladesh / Pakistan ---
        "Bangladesh Passport" | "Pakistan Passport" => 0.80,
        "Bangladesh NID" | "Bangladesh TIN" => 0.70,
        "Pakistan CNIC" | "Pakistan NICOP" => 0.70,

        // --- Australia / New Zealand ---
        "Australia Passport" | "New Zealand Passport" => 0.80,
        "Australia TFN" | "Australia Medicare" => 0.70,
        "Australia DL ACT" | "Australia DL NSW" | "Australia DL NT"
        | "Australia DL QLD" | "Australia DL SA" | "Australia DL TAS"
        | "Australia DL VIC" | "Australia DL WA" => 0.70,
        "New Zealand IRD" | "New Zealand NHI" => 0.70,
        "New Zealand DL" => 0.55,

        // --- Middle East ---
        "Saudi Arabia Passport" | "UAE Passport" | "Kuwait Passport"
        | "Qatar Passport" | "Bahrain Passport" | "Jordan Passport"
        | "Lebanon Passport" | "Iran Passport" | "Iraq Passport"
        | "Israel Passport" => 0.80,
        "Saudi Arabia National ID" => 0.70,
        "UAE Emirates ID" | "UAE Visa Number" => 0.70,
        "Kuwait Civil ID" => 0.70,
        "Qatar QID" => 0.70,
        "Bahrain CPR" => 0.70,
        "Jordan National ID" => 0.70,
        "Lebanon ID" => 0.70,
        "Iran Melli Code" => 0.70,
        "Iraq National ID" => 0.70,
        "Israel Teudat Zehut" => 0.70,

        // --- Africa ---
        "South Africa Passport" | "Nigeria Passport" | "Kenya Passport"
        | "Ghana Passport" | "Ethiopia Passport" | "Uganda Passport"
        | "Morocco Passport" | "Egypt Passport" | "Tunisia Passport"
        | "Tanzania Passport" => 0.80,
        "South Africa ID" => 0.65,
        "South Africa DL" => 0.55,
        "Nigeria NIN" | "Nigeria BVN" | "Nigeria TIN" | "Nigeria Voter Card"
        | "Nigeria Driver Licence" => 0.65,
        "Kenya National ID" | "Kenya KRA PIN" | "Kenya NHIF" => 0.65,
        "Ghana Card" | "Ghana TIN" | "Ghana NHIS" => 0.65,
        "Ethiopia National ID" | "Ethiopia TIN" => 0.65,
        "Uganda NIN" => 0.65,
        "Morocco CIN" | "Morocco Tax ID" => 0.65,
        "Egypt National ID" | "Egypt Tax ID" => 0.65,
        "Tunisia CIN" => 0.65,
        "Tanzania NIDA" | "Tanzania TIN" => 0.65,

        // --- Latin America ---
        "Brazil Passport" | "Mexico Passport" | "Argentina Passport"
        | "Colombia Passport" | "Chile Passport" | "Peru Passport"
        | "Ecuador Passport" | "Venezuela Passport" | "Uruguay Passport"
        | "Paraguay Passport" | "Costa Rica Passport" => 0.80,
        "Brazil CPF" | "Brazil CNPJ" | "Brazil RG" | "Brazil CNH"
        | "Brazil SUS Card" => 0.70,
        "Mexico CURP" | "Mexico RFC" | "Mexico NSS" | "Mexico Clave Elector"
        | "Mexico INE CIC" | "Mexico INE OCR" => 0.70,
        "Argentina DNI" | "Argentina CUIL/CUIT" => 0.70,
        "Colombia Cedula" | "Colombia NIT" | "Colombia NUIP" => 0.70,
        "Chile RUN/RUT" => 0.70,
        "Peru DNI" | "Peru RUC" | "Peru Carnet Extranjeria" => 0.70,
        "Ecuador Cedula" | "Ecuador RUC" => 0.70,
        "Venezuela Cedula" | "Venezuela RIF" => 0.70,
        "Uruguay Cedula" | "Uruguay RUT" => 0.70,
        "Paraguay Cedula" | "Paraguay RUC" => 0.70,
        "Costa Rica Cedula" | "Costa Rica DIMEX" => 0.70,

        // --- Date patterns ---
        "Date ISO" | "Date US" | "Date EU" => 0.35,

        // --- Postal codes (not already scored) ---

        // --- Classification labels ---
        "Top Secret" | "Secret Classification" | "Confidential Classification"
        | "Highly Confidential" | "Restricted" | "FOUO" | "NOFORN" | "Eyes Only"
        | "SBU" | "CUI" | "CSI" | "LES" => 0.45,
        "Corporate Confidential" | "Internal Only" | "Proprietary"
        | "Do Not Distribute" | "Draft Not for Circulation"
        | "Embargoed" | "Need to Know" => 0.45,

        // --- Financial regulatory / market labels ---
        "MNPI" | "Inside Information" | "Market Sensitive"
        | "Investment Restricted" | "Information Barrier"
        | "Non-Public Supervisory" | "Supervisory Confidential"
        | "Supervisory Controlled" | "Restricted Supervisory"
        | "Pre-Decisional" | "Examination Findings" => 0.45,

        // --- Legal / privilege markers ---
        "Legal Privilege" | "Attorney-Client Privilege" | "Work Product"
        | "Privileged and Confidential" | "Privileged Information"
        | "Protected by Privilege" | "Litigation Hold" => 0.45,

        // --- Compliance patterns ---
        "PII Label" | "PHI Label" | "PCI-DSS" | "HIPAA" | "GDPR Personal Data"
        | "CCPA/CPRA" | "FERPA" | "GLBA" | "SOX" => 0.45,

        // --- Secrets (additional) ---
        "Generic Secret Assignment" => 0.50,

        _ => DEFAULT_SPECIFICITY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_match(text: &str) -> Match {
        Match::new(
            text.to_string(),
            "Credit Card Numbers".to_string(),
            "Visa".to_string(),
            true,
            0.9,
            (0, text.len()),
            false,
        )
    }

    #[test]
    fn test_match_new() {
        let m = sample_match("4111111111111111");
        assert_eq!(m.category, "Credit Card Numbers");
        assert_eq!(m.sub_category, "Visa");
        assert!(m.has_context);
        assert_eq!(m.confidence, 0.9);
        assert_eq!(m.span, (0, 16));
        assert!(!m.context_required);
    }

    #[test]
    fn test_redacted_text_short() {
        let m = sample_match("secret");
        assert_eq!(m.redacted_text(), "******");
    }

    #[test]
    fn test_redacted_text_long() {
        let m = sample_match("4111111111111111");
        let redacted = m.redacted_text();
        assert!(redacted.starts_with("411"));
        assert!(redacted.ends_with("111"));
        assert!(redacted.contains('*'));
        assert_eq!(redacted.len(), 16);
    }

    #[test]
    fn test_to_dict_not_redacted() {
        let m = sample_match("4111111111111111");
        let val = m.to_dict(false);
        assert_eq!(val["text"], "4111111111111111");
    }

    #[test]
    fn test_to_dict_redacted() {
        let m = sample_match("4111111111111111");
        let val = m.to_dict(true);
        assert_ne!(val["text"], "4111111111111111");
        assert!(val["text"].as_str().unwrap().contains('*'));
    }

    #[test]
    fn test_pattern_specificity_known() {
        assert_eq!(pattern_specificity("Visa"), 0.90);
        assert_eq!(pattern_specificity("Email Address"), 0.90);
        assert_eq!(pattern_specificity("JWT Token"), 0.95);
    }

    #[test]
    fn test_pattern_specificity_unknown_returns_default() {
        assert_eq!(pattern_specificity("NoSuchPattern"), DEFAULT_SPECIFICITY);
    }

    #[test]
    fn test_context_required() {
        assert!(is_context_required("US Bank Account Number"));
        assert!(is_context_required("Card Expiry"));
        assert!(!is_context_required("Visa"));
        assert!(!is_context_required("Email Address"));
    }

    #[test]
    fn test_redacted_text_multibyte() {
        let m = sample_match("テスト日本語データ"); // 8 chars, 24 bytes
        let redacted = m.redacted_text();
        // len() is 24 bytes (>8), so redacted_text uses first 3 + stars + last 3 chars
        assert!(redacted.starts_with("テスト"));
        assert!(redacted.ends_with("データ"));
        assert!(redacted.contains('*'));
    }
}

/// Patterns that REQUIRE context to be reported.
/// These are patterns so broad that without context keywords nearby,
/// they produce too many false positives.
pub fn is_context_required(sub_category: &str) -> bool {
    matches!(
        sub_category,
        "US Bank Account Number"
            | "ACH Batch Number"
            | "Check Number"
            | "Cashier Check Number"
            | "OFAC SDN Entry"
            | "Cardholder Name Pattern"
            | "Gender Marker"
            | "Hashtag"
            | "Card Expiry"
            | "Date of Birth"
            | "LTV Ratio"
            | "DTI Ratio"
    )
}
