import React, { useState } from 'react';
import { Shield, Zap, Search, AlertTriangle, CheckCircle, XCircle, Loader, Globe, Code, Settings, FileX, Upload, Terminal, Key, Bomb } from 'lucide-react';
import Navbar from '../components/Navbar';


// TODO: Integrate UI with the backend.. deadline: 24th Aug EOD😭

// Define the data for different attack types.
// This is an array of objects, which works in both JS and TS.
const attackTypes = [
  { id: 'sql-injection', name: 'SQL Injection', description: 'Tests for database injection vulnerabilities', icon: <Code className="w-4 h-4" />, severity: 'critical' },
  { id: 'xss', name: 'Cross-Site Scripting (XSS)', description: 'Detects script injection vulnerabilities', icon: <Terminal className="w-4 h-4" />, severity: 'high' },
  { id: 'csrf', name: 'Cross-Site Request Forgery', description: 'Checks for CSRF protection mechanisms', icon: <Shield className="w-4 h-4" />, severity: 'medium' },
  { id: 'directory-traversal', name: 'Directory Traversal', description: 'Tests for unauthorized file access', icon: <FileX className="w-4 h-4" />, severity: 'high' },
  { id: 'insecure-deserialization', name: 'Insecure Deserialization', description: 'Detects vulnerabilities in data deserialization', icon: <Settings className="w-4 h-4" />, severity: 'critical' },
  { id: 'cmd-injection', name: 'Command Injection', description: 'Tests for OS command injection vulnerabilities', icon: <Terminal className="w-4 h-4" />, severity: 'critical' },
  { id: 'jwt-manipulation', name: 'JWT Manipulation', description: 'Checks for JSON Web Token vulnerabilities', icon: <Key className="w-4 h-4" />, severity: 'high' },
  { id: 'file-upload', name: 'File Upload Vulnerabilities', description: 'Tests for malicious file upload vulnerabilities', icon: <Upload className="w-4 h-4" />, severity: 'high' },
  { id: 'ddos', name: 'DDoS Simulation', description: 'Tests for resilience against denial-of-service attacks', icon: <Bomb className="w-4 h-4" />, severity: 'medium' }
];

const Dashboard = () => {
  const [domain, setDomain] = useState('');
  const [selectedAttacks, setSelectedAttacks] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanResults, setScanResults] = useState([]);
  const [currentScan, setCurrentScan] = useState('');

  // Toggle attacks
  const handleAttackToggle = (attackId) => {
    setSelectedAttacks((prev) =>
      prev.includes(attackId) ? prev.filter((id) => id !== attackId) : [...prev, attackId]
    );
  };

  const selectAllAttacks = () => {
    if (selectedAttacks.length === attackTypes.length) {
      setSelectedAttacks([]);
    } else {
      setSelectedAttacks(attackTypes.map((a) => a.id));
    }
  };

  // 🔹 Start scan (real API call + simulated results)
  const startScan = async () => {
    if (!domain || selectedAttacks.length === 0) return;

    setIsScanning(true);
    setScanProgress(0);
    setScanResults([]);

    // 🔹 Fire backend API call (runs in background)
    try {
      const token = localStorage.getItem('ACCESS_TOKEN');
      // console.log("[LOCALSTORAGE TOKEN]", token);
      const res = await fetch('http://localhost:5001/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {})
        },
        body: JSON.stringify({ domain, attacks: selectedAttacks })
      });

      if (!res.ok) {
        console.error('[SCAN API ERROR]', await res.json());
      } else {
        const data = await res.json();
        console.log('[SCAN API RESPONSE]', data);
      }
    } catch (err) {
      console.error('API call failed:', err);
    }

    // 🔹 Simulate scanning & fake results
    for (let i = 0; i < selectedAttacks.length; i++) {
      const attackId = selectedAttacks[i];
      const attack = attackTypes.find((a) => a.id === attackId);
      setCurrentScan(attack?.name || '');

      await new Promise((resolve) => setTimeout(resolve, 2000));

      const statuses = ['vulnerable', 'secure', 'warning'];
      const status = statuses[Math.floor(Math.random() * statuses.length)];

      const result = {
        attackType: attack?.name || '',
        status,
        details: getResultDetails(attackId, status),
        recommendation: status === 'vulnerable' ? getRecommendation(attackId) : undefined
      };

      setScanResults((prev) => [...prev, result]);
      setScanProgress(((i + 1) / selectedAttacks.length) * 100);
    }

    setIsScanning(false);
    setCurrentScan('');
  };

  // Dummy details for UI
  const getResultDetails = (attackId, status) => {
    const details = {
      'sql-injection': {
        vulnerable: 'SQL injection vulnerability detected in login form',
        secure: 'No SQL injection vulnerabilities found',
        warning: 'Potential SQL injection risk detected'
      },
      xss: {
        vulnerable: 'Stored XSS vulnerability found in comment section',
        secure: 'No XSS vulnerabilities detected',
        warning: 'Input validation could be improved'
      },
      csrf: {
        vulnerable: 'CSRF tokens missing on critical forms',
        secure: 'CSRF protection properly implemented',
        warning: 'CSRF protection partially implemented'
      },
      'directory-traversal': {
        vulnerable: 'Directory traversal vulnerability detected',
        secure: 'No directory traversal vulnerabilities found',
        warning: 'Input validation for file paths should be strengthened'
      },
      'insecure-deserialization': {
        vulnerable: 'Insecure deserialization vulnerability detected',
        secure: 'Deserialization is secure',
        warning: 'Review deserialization process for potential risks'
      },
      'cmd-injection': {
        vulnerable: 'OS command injection vulnerability detected',
        secure: 'No command injection vulnerabilities found',
        warning: 'Check input sanitization on system calls'
      },
      'jwt-manipulation': {
        vulnerable: 'JWT token manipulation detected',
        secure: 'JWT tokens are properly signed and verified',
        warning: 'Check for weak signing algorithms or expired tokens'
      },
      'file-upload': {
        vulnerable: 'Malicious file upload vulnerability detected',
        secure: 'File uploads are secure',
        warning: 'File type validation needs improvement'
      },
      ddos: {
        vulnerable: 'System is vulnerable to DDoS attack',
        secure: 'System is resilient to DDoS attack',
        warning: 'Review rate limiting and protection measures'
      }
    };
    return details[attackId]?.[status] || `${status} detected`;
  };

  const getRecommendation = (attackId) => {
    const recs = {
      'sql-injection': 'Use parameterized queries and input validation',
      xss: 'Sanitize inputs and add Content Security Policy',
      csrf: 'Add CSRF tokens to all forms',
      'directory-traversal': 'Sanitize file paths strictly',
      'insecure-deserialization': 'Avoid deserializing untrusted data',
      'cmd-injection': 'Avoid executing shell commands from user input',
      'jwt-manipulation': 'Use strong signing keys and validate claims',
      'file-upload': 'Validate file types and store securely',
      ddos: 'Implement rate limiting and use DDoS protection services'
    };
    return recs[attackId] || 'Review security measures';
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'text-red-400';
      case 'high': return 'text-orange-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-blue-400';
      default: return 'text-gray-400';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'vulnerable': return <XCircle className="w-5 h-5 text-red-400" />;
      case 'secure': return <CheckCircle className="w-5 h-5 text-green-400" />;
      case 'warning': return <AlertTriangle className="w-5 h-5 text-yellow-400" />;
      default: return null;
    }
  };

  // The main JSX for the application.
  return (
    <div className="min-h-screen bg-gray-900 text-green-400 font-mono relative overflow-x-hidden">
      {/* Background Grid Pattern */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(0,255,65,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,255,65,0.03)_1px,transparent_1px)] bg-[size:50px_50px]"></div>

      {/* Navbar */}
      <Navbar />

      {/* Main Scanner Interface. A top padding of pt-28 is added to prevent content overlap. */}
      <div className="relative z-10 container mx-auto px-6 pt-28 pb-8">
        <div className="text-center mb-12">
          <div className="flex items-center justify-center mb-4">
            <Shield className="w-12 h-12 text-green-400 mr-4" />
            <h1 className="text-4xl md:text-6xl font-bold text-white tracking-wider">
              VULN<span className="text-green-400">ORA</span>
            </h1>
          </div>
          <p className="text-lg text-gray-400 max-w-2xl mx-auto">
            Advanced Web Application Security Scanner
          </p>
          <div className="w-24 h-1 bg-gradient-to-r from-transparent via-green-400 to-transparent mx-auto mt-4"></div>
        </div>

        {/* Main Scanner Interface */}
        <div className="max-w-4xl mx-auto">
          {/* Domain Input Section */}
          <div className="bg-black/40 backdrop-blur-sm border border-green-400/20 rounded-lg p-6 mb-8 shadow-2xl">
            <h2 className="text-xl font-bold text-white mb-4 flex items-center">
              <Globe className="w-5 h-5 mr-2" />
              Target Domain
            </h2>
            <div className="flex gap-4">
              <div className="flex-1 relative">
                <input
                  type="text"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="Enter domain (e.g., example.com)"
                  className="w-full bg-gray-800/50 border border-green-400/30 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:border-green-400 focus:ring-2 focus:ring-green-400/20 focus:outline-none transition-all"
                  disabled={isScanning}
                />
                <div className="absolute inset-0 bg-green-400/5 rounded-lg pointer-events-none opacity-0 hover:opacity-100 transition-opacity"></div>
              </div>
            </div>
          </div>

          {/* Attack Selection Section */}
          <div className="bg-black/40 backdrop-blur-sm border border-green-400/20 rounded-lg p-6 mb-8 shadow-2xl">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-white flex items-center">
                <Zap className="w-5 h-5 mr-2" />
                Attack Vectors
              </h2>
              <button
                onClick={selectAllAttacks}
                className="text-sm text-green-400 hover:text-white transition-colors px-3 py-1 border border-green-400/30 rounded hover:border-green-400"
                disabled={isScanning}
              >
                {selectedAttacks.length === attackTypes.length ? 'Deselect All' : 'Select All'}
              </button>
            </div>

            <div className="grid md:grid-cols-2 gap-4">
              {attackTypes.map((attack) => (
                <div
                  key={attack.id}
                  className={`border border-gray-700 rounded-lg p-4 cursor-pointer transition-all hover:border-green-400/50 ${
                    selectedAttacks.includes(attack.id)
                      ? 'bg-green-400/10 border-green-400/50'
                      : 'hover:bg-gray-800/50'
                  }`}
                  onClick={() => !isScanning && handleAttackToggle(attack.id)}
                >
                  <div className="flex items-start gap-3">
                    <div className={`mt-1 ${selectedAttacks.includes(attack.id) ? 'text-green-400' : 'text-gray-500'}`}>
                      {attack.icon}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <h3 className={`font-semibold ${selectedAttacks.includes(attack.id) ? 'text-white' : 'text-gray-300'}`}>
                          {attack.name}
                        </h3>
                        <span className={`text-xs px-2 py-1 rounded ${getSeverityColor(attack.severity)} bg-current/10`}>
                          {attack.severity.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-sm text-gray-500">{attack.description}</p>
                    </div>
                    <div className={`w-5 h-5 rounded border-2 flex items-center justify-center ${
                      selectedAttacks.includes(attack.id)
                        ? 'bg-green-400 border-green-400'
                        : 'border-gray-600'
                    }`}>
                      {selectedAttacks.includes(attack.id) && (
                        <CheckCircle className="w-3 h-3 text-black" />
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Scan Button Section */}
          <div className="text-center mb-8">
            <button
              onClick={startScan}
              disabled={!domain || selectedAttacks.length === 0 || isScanning}
              className="bg-gradient-to-r from-green-400 to-emerald-500 hover:from-green-500 hover:to-emerald-600 disabled:from-gray-600 disabled:to-gray-700 text-black font-bold py-4 px-8 rounded-lg text-lg transition-all transform hover:scale-105 disabled:scale-100 disabled:cursor-not-allowed shadow-xl"
            >
              {isScanning ? (
                <span className="flex items-center">
                  <Loader className="w-5 h-5 mr-2 animate-spin" />
                  Scanning...
                </span>
              ) : (
                <span className="flex items-center">
                  <Search className="w-5 h-5 mr-2" />
                  Start Security Scan
                </span>
              )}
            </button>
          </div>

          {/* Progress Bar Section */}
          {isScanning && (
            <div className="bg-black/40 backdrop-blur-sm border border-green-400/20 rounded-lg p-6 mb-8">
              <div className="flex justify-center mb-8">
                <Loader size={64} strokeWidth={1} className="animate-spin text-green-400" />
              </div>
              <div className="flex justify-center mb-8">
                Attacks are being simulated.. Analysing the response..
              </div>
            </div>
          )}

          {/* Results Section */}
          {scanResults.length > 0 && (
            <div className="bg-black/40 backdrop-blur-sm border border-green-400/20 rounded-lg p-6 shadow-2xl">
              <h2 className="text-xl font-bold text-white mb-6 flex items-center">
                <AlertTriangle className="w-5 h-5 mr-2" />
                Scan Results
              </h2>

              <div className="space-y-4">
                {scanResults.map((result, index) => (
                  <div
                    key={index}
                    className={`border rounded-lg p-4 ${
                      result.status === 'vulnerable' ? 'border-red-400/30 bg-red-400/5' :
                      result.status === 'secure' ? 'border-green-400/30 bg-green-400/5' :
                      'border-yellow-400/30 bg-yellow-400/5'
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      {getStatusIcon(result.status)}
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <h3 className="font-semibold text-white">{result.attackType}</h3>
                          <span className={`text-xs px-2 py-1 rounded font-medium ${
                            result.status === 'vulnerable' ? 'bg-red-400/20 text-red-400' :
                            result.status === 'secure' ? 'bg-green-400/20 text-green-400' :
                            'bg-yellow-400/20 text-yellow-400'
                          }`}>
                            {result.status.toUpperCase()}
                          </span>
                        </div>
                        <p className="text-gray-300 mb-2">{result.details}</p>
                        {result.recommendation && (
                          <div className="bg-gray-800/50 rounded p-3 mt-2">
                            <p className="text-sm text-blue-400 font-semibold mb-1">Recommendation:</p>
                            <p className="text-sm text-gray-300">{result.recommendation}</p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Summary Section */}
              <div className="mt-6 pt-6 border-t border-gray-700">
                <div className="grid grid-cols-3 gap-4 text-center">
                  <div>
                    <div className="text-2xl font-bold text-red-400">
                      {scanResults.filter(r => r.status === 'vulnerable').length}
                    </div>
                    <div className="text-sm text-gray-400">Vulnerabilities</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-yellow-400">
                      {scanResults.filter(r => r.status === 'warning').length}
                    </div>
                    <div className="text-sm text-gray-400">Warnings</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-green-400">
                      {scanResults.filter(r => r.status === 'secure').length}
                    </div>
                    <div className="text-sm text-gray-400">Secure</div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
