import React from 'react';
import Navbar from '../components/Navbar';
import { History } from 'lucide-react';

// TODO: Integrate UI with the backend.. deadline: 24th Aug EOD😭
// Dummy history data for past reports based on the new attack vectors.
const dummyReports = [
  {
    id: 'rep-001',
    website: 'cyberdynesystems.com',
    tags: ['sqli', 'xss'],
    report: 'A critical SQL Injection vulnerability was found in the user authentication form. Additionally, a stored Cross-Site Scripting (XSS) vulnerability was detected in the contact form, which could be used to compromise other users.',
    createdAt: new Date('2024-08-22T10:00:00Z'),
  },
  {
    id: 'rep-002',
    website: 'skynet.ai',
    tags: ['csrf', 'jwt-manipulation'],
    report: 'This site is generally secure, but a medium-severity Cross-Site Request Forgery (CSRF) vulnerability was identified on the password reset form. Further analysis showed a potential for JWT (JSON Web Token) manipulation.',
    createdAt: new Date('2024-08-20T14:30:00Z'),
  },
  {
    id: 'rep-003',
    website: 'sentinelsecurity.org',
    tags: ['cmd-injection', 'file-upload'],
    report: 'A high-severity Command Injection vulnerability was found, allowing remote code execution. A file upload vulnerability was also identified, which could allow an attacker to upload malicious scripts.',
    createdAt: new Date('2024-08-18T09:15:00Z'),
  },
  {
    id: 'rep-004',
    website: 'omega-protocol.net',
    tags: ['dir-traversal', 'insecure-deserialization'],
    report: 'The server is vulnerable to directory traversal, allowing unauthorized access to system files. Additionally, an insecure deserialization flaw was detected, which could lead to remote code execution.',
    createdAt: new Date('2024-08-15T18:00:00Z'),
  },
  {
    id: 'rep-005',
    website: 'defensive-measures.com',
    tags: ['ddos', 'sqli'],
    report: 'The website is resilient to DDoS attacks, but a low-severity SQL Injection vulnerability was found in a secondary search feature.',
    createdAt: new Date('2024-08-14T11:45:00Z'),
  },
];

/**
 * Renders the History page of the Vulnora application.
 * Displays a list of past security scan reports with full UI.
 * This component is self-contained and does not require a parent component for styling.
 */
const HistoryPage = () => {
  return (
    <div className="min-h-screen bg-gray-900 text-green-400 font-mono relative overflow-x-hidden">
      {/* Background Grid Pattern */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(0,255,65,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,255,65,0.03)_1px,transparent_1px)] bg-[size:50px_50px]"></div>

      <Navbar />
      {/* Main Content Container */}
      <div className="relative z-10 container mx-auto px-6 pt-28 pb-8">
        <div className="text-center mb-12">
          <div className="flex items-center justify-center mb-4">
            <History className="w-12 h-12 text-green-400 mr-4" />
            <h1 className="text-4xl md:text-6xl font-bold text-white tracking-wider">
              SCAN <span className="text-green-400">HISTORY</span>
            </h1>
          </div>
          <p className="text-lg text-gray-400 max-w-2xl mx-auto">
            Review past security reports for monitored websites.
          </p>
          <div className="w-24 h-1 bg-gradient-to-r from-transparent via-green-400 to-transparent mx-auto mt-4"></div>
        </div>

        {/* Reports List */}
        <div className="max-w-4xl mx-auto">
          {dummyReports.length === 0 ? (
            <div className="text-center text-gray-500">No past reports found.</div>
          ) : (
            <div className="space-y-6">
              {dummyReports.map((report) => (
                <div
                  key={report.id}
                  className="bg-black/40 backdrop-blur-sm border border-green-400/20 rounded-lg p-6 shadow-2xl transition-transform transform hover:scale-[1.01] hover:border-green-400/50"
                >
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <h2 className="text-2xl font-bold text-white mb-1">{report.website}</h2>
                      <p className="text-sm text-gray-500">
                        Scanned on: {report.createdAt.toLocaleDateString()} at {report.createdAt.toLocaleTimeString()}
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-2 mt-1">
                      {report.tags.map(tag => (
                        <span
                          key={tag}
                          className="text-xs px-2 py-1 rounded-full font-medium text-green-400 bg-green-400/10"
                        >
                          {tag.toUpperCase().replace('-', ' ')}
                        </span>
                      ))}
                    </div>
                  </div>
                  <p className="text-gray-300 leading-relaxed">
                    {report.report}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default HistoryPage;
