/* 
    Vulnerable Static JS File
    Designed to trigger the JS Analyzer tool in VulnScan Pro.
*/

var appConfig = {
    // AWS Access Key (simulated)
    aws_key: "AKIAIOSFODNN7EXAMPLE",
    
    // GitHub Personal Access Token (simulated)
    github_token: "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890",
    
    // Internal network IPs
    dbHost: "192.168.1.150",
    localCache: "http://localhost:6379",
    
    // Hardcoded dev credentials
    // password: 'SuperS3curePassword!'
    admin_hash: "admin:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    
    // Exposed API Endpoint
    apiUrl: "/api/v1/internal/health",
    
    // TODO: FIX ME! Remove these credentials before pushing to production!
};
