import React, { useState } from 'react';
import { Shield, Zap, Search, AlertTriangle, CheckCircle, XCircle, Loader, Globe, Code, Settings, FileX, Upload, Terminal, Key, Bomb, ChevronDown, ChevronUp, Copy } from 'lucide-react';
import Navbar from '../components/Navbar';

// Define attack types
const attackTypes = [
  { id: 'sql_injection', name: 'SQL Injection', description: 'Tests for database injection vulnerabilities', icon: <Code className="w-4 h-4" />, severity: 'critical' },
  //{ id: 'Cross-Site Scripting', name: 'Cross-Site Scripting (XSS)', description: 'Detects script injection vulnerabilities', icon: <Terminal className="w-4 h-4" />, severity: 'high' },
  //{ id: 'csrf', name: 'Cross-Site Request Forgery', description: 'Checks for CSRF protection mechanisms', icon: <Shield className="w-4 h-4" />, severity: 'medium' },
  { id: 'path_traversal', name: 'Directory Traversal', description: 'Tests for unauthorized file access', icon: <FileX className="w-4 h-4" />, severity: 'high' },
  { id: 'insecure_deserialization', name: 'Insecure Deserialization', description: 'Detects vulnerabilities in data deserialization', icon: <Settings className="w-4 h-4" />, severity: 'critical' },
  { id: 'cmd_injection', name: 'Command Injection', description: 'Tests for OS command injection vulnerabilities', icon: <Terminal className="w-4 h-4" />, severity: 'critical' },
  { id: 'jwt', name: 'JWT Manipulation', description: 'Checks for JSON Web Token vulnerabilities', icon: <Key className="w-4 h-4" />, severity: 'high' },
  { id: 'file_upload', name: 'File Upload Vulnerabilities', description: 'Tests for malicious file upload vulnerabilities', icon: <Upload className="w-4 h-4" />, severity: 'high' },
  { id: 'ddos', name: 'DDoS Simulation', description: 'Tests for resilience against denial-of-service attacks', icon: <Bomb className="w-4 h-4" />, severity: 'medium' },
  { id: 'IP Scratching', name: 'IP Scratching', description: 'Analyzes URL and collects logs', icon: <Globe className="w-4 h-4" />, severity: 'medium' }
];

const Dashboard = () => {
  const [domain, setDomain] = useState('');
  const [selectedAttacks, setSelectedAttacks] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanResults, setScanResults] = useState([]);
  const [currentScan, setCurrentScan] = useState('');
  const [expandedLogs, setExpandedLogs] = useState({});

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

  // Toggle logs expansion
  const toggleLogs = (attackId) => {
    setExpandedLogs((prev) => ({ ...prev, [attackId]: !prev[attackId] }));
  };

  // Copy logs to clipboard
  const copyLogs = (logs) => {
    navigator.clipboard.writeText(JSON.stringify(logs, null, 2));
  };

  // Determine status
  const determineStatus = (result) => {
    if (result.vulnerable === true || result.error || result.vulnerability_detected) {
      return 'vulnerable';
    } else if (result.warning || result.potential_risk) {
      return 'warning';
    } else {
      return 'secure';
    }
  };

  const getSummaryDetails = (result) => {
    if (result.summary || result.message) {
      return result.summary || result.message;
    } else if (typeof result === 'string') {
      return result;
    } else {
      return 'Scan completed. Check logs for details.';
    }
  };

  // Start scan
  const startScan = async () => {
    if (!domain || selectedAttacks.length === 0) return;

    setIsScanning(true);
    setScanProgress(0);
    setScanResults([]);
    setExpandedLogs({});

    try {
      const token = localStorage.getItem('ACCESS_TOKEN');
      const baseURL = 'http://localhost:5001';
      const res = await fetch(`${baseURL}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {})
        },
        body: JSON.stringify({ domain, attacks: selectedAttacks })
      });

      if (!res.ok) {
        const errorData = await res.json();
        console.error('[SCAN API ERROR]', errorData);
        setScanResults([{ attackType: 'Error', status: 'vulnerable', details: errorData.message || 'Scan failed' }]);
      } else {
        const data = await res.json();
        console.log('[SCAN API RESPONSE]', data);

        const processedResults = Object.entries(data.result?.results || {}).map(([attackType, rawResult]) => {
          const status = determineStatus(rawResult);
          return {
            attackType,
            status,
            details: getSummaryDetails(rawResult),
            fullLogs: rawResult,
            recommendation: rawResult.recommendation || (status === 'vulnerable' ? 'Review the logs and apply security fixes.' : undefined)
          };
        });

        setScanResults(processedResults);
        setScanProgress(100);
      }
    } catch (err) {
      console.error('API call failed:', err);
      setScanResults([{ attackType: 'Network Error', status: 'vulnerable', details: 'Failed to connect to the scanner service.' }]);
    }

    setIsScanning(false);
    setCurrentScan('');
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

  return (
    <div className="min-h-screen bg-gray-900 text-green-400 font-mono relative overflow-x-hidden">
      <div className="absolute inset-0 bg-[linear-gradient(rgba(0,255,65,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,255,65,0.03)_1px,transparent_1px)] bg-[size:50px_50px]"></div>
      <Navbar />
      <div className="relative z-10 container mx-auto px-6 pt-28 pb-8">
        <div className="text-center mb-12">
          <div className="flex items-center justify-center mb-4">
            <Shield className="w-12 h-12 text-green-400 mr-4" />
            <h1 className="text-4xl md:text-6xl font-bold text-white tracking-wider">
              VULN<span className="text-green-400">ORA</span>
            </h1>
          </div>
          <p className="text-lg text-gray-400 max-w-2xl mx-auto">Advanced Web Application Security Scanner</p>
          <div className="w-24 h-1 bg-gradient-to-r from-transparent via-green-400 to-transparent mx-auto mt-4"></div>
        </div>

        {/* Domain Input */}
        <div className="bg-black/40 backdrop-blur-sm border border-green-400/20 rounded-lg p-6 mb-8 shadow-2xl">
          <h2 className="text-xl font-bold text-white mb-4 flex items-center">
            <Globe className="w-5 h-5 mr-2" /> Target Domain
          </h2>
          <div className="flex gap-4">
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="Enter domain (e.g., example.com)"
              className="w-full bg-gray-800/50 border border-green-400/30 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:border-green-400 focus:ring-2 focus:ring-green-400/20 focus:outline-none transition-all"
              disabled={isScanning}
            />
          </div>
        </div>

        {/* Attack Selection */}
        <div className="bg-black/40 backdrop-blur-sm border border-green-400/20 rounded-lg p-6 mb-8 shadow-2xl">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-bold text-white flex items-center">
              <Zap className="w-5 h-5 mr-2" /> Attack Vectors
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
                  selectedAttacks.includes(attack.id) ? 'bg-green-400/10 border-green-400/50' : 'hover:bg-gray-800/50'
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
                    selectedAttacks.includes(attack.id) ? 'bg-green-400 border-green-400' : 'border-gray-600'
                  }`}>
                    {selectedAttacks.includes(attack.id) && <CheckCircle className="w-3 h-3 text-black" />}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Scan Button */}
        <div className="text-center mb-8">
          <button
            onClick={startScan}
            disabled={!domain || selectedAttacks.length === 0 || isScanning}
            className="bg-gradient-to-r from-green-400 to-emerald-500 hover:from-green-500 hover:to-emerald-600 disabled:from-gray-600 disabled:to-gray-700 text-black font-bold py-4 px-8 rounded-lg text-lg transition-all transform hover:scale-105 disabled:scale-100 disabled:cursor-not-allowed shadow-xl"
          >
            {isScanning ? (
              <span className="flex items-center">
                <Loader className="w-5 h-5 mr-2 animate-spin" /> Scanning...
              </span>
            ) : (
              <span className="flex items-center">
                <Search className="w-5 h-5 mr-2" /> Start Security Scan
              </span>
            )}
          </button>
        </div>

        {/* Progress Bar */}
        {isScanning && (
          <div className="bg-black/40 backdrop-blur-sm border border-green-400/20 rounded-lg p-6 mb-8">
            <div className="flex justify-center mb-8">
              <Loader size={64} strokeWidth={1} className="animate-spin text-green-400" />
            </div>
            <div className="flex justify-center mb-8">
              <div className="w-full bg-gray-700 rounded-full h-2.5">
                <div className="bg-green-400 h-2.5 rounded-full transition-all duration-300" style={{ width: `${scanProgress}%` }}></div>
              </div>
            </div>
            <div className="text-center">
              <p className="text-gray-400">Currently scanning: {currentScan || 'Initializing...'}</p>
            </div>
          </div>
        )}

        {/* Results */}
        {scanResults.length > 0 && (
          <div className="bg-black/40 backdrop-blur-sm border border-green-400/20 rounded-lg p-6 shadow-2xl">
            <h2 className="text-xl font-bold text-white mb-6 flex items-center">
              <AlertTriangle className="w-5 h-5 mr-2" /> Scan Results
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

                      {/* 🔹 RAW LOGS SECTION */}
                      {result.fullLogs && (
                        <div className="mt-4">
                          <button
                            onClick={() => toggleLogs(result.attackType)}
                            className="cursor-pointer flex items-center gap-2 text-green-400 hover:text-green-300 font-medium mb-2 w-full text-left bg-transparent border-none p-0"
                          >
                            {expandedLogs[result.attackType] ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                            View Raw Logs
                            <Copy 
                              className="w-4 h-4 ml-auto cursor-pointer hover:text-white" 
                              onClick={(e) => { e.stopPropagation(); copyLogs(result.fullLogs); }} 
                              title="Copy logs"
                            />
                          </button>
                          {expandedLogs[result.attackType] && (
                            <div className="mt-2 p-3 bg-black/50 rounded border border-gray-700 overflow-auto max-h-60">
                              <pre className="text-xs text-gray-300 whitespace-pre-wrap">
                                {JSON.stringify(result.fullLogs, null, 2)}
                              </pre>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Summary */}
            <div className="mt-6 pt-6 border-t border-gray-700">
              <div className="grid grid-cols-3 gap-4 text-center">
                <div>
                  <div className="text-2xl font-bold text-red-400">{scanResults.filter(r => r.status === 'vulnerable').length}</div>
                  <div className="text-sm text-gray-400">Vulnerabilities</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-yellow-400">{scanResults.filter(r => r.status === 'warning').length}</div>
                  <div className="text-sm text-gray-400">Warnings</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-green-400">{scanResults.filter(r => r.status === 'secure').length}</div>
                  <div className="text-sm text-gray-400">Secure</div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;
