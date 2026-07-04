// Test fixture with PII for scanner validation
// This file should NOT be committed to a real repo

const userData = {
  bsn: "123456782", // valid elfproef test number
  iban: "NL91ABNA0417164300",
  email: "test@example.com", // should be excluded
  workEmail: "john@company.nl", // should match
  phone: "06-12345678",
  postalCode: "1234 AB",
};

// KvK context
const company = {
  kvkNumber: "12345678", // should match (handelsregister context nearby)
  register: "handelsregister",
};

module.exports = { userData, company };
