import React, { useEffect, useState } from "react";
import Navbar from "../components/Navbar";
import { History } from "lucide-react";
import axios from "axios";

const HistoryPage = () => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchReports = async () => {
      try {
        setLoading(true);
        setError("");

        const token = localStorage.getItem("ACCESS_TOKEN");
        if (!token) {
          setError("Authentication required. Please log in.");
          setLoading(false);
          return;
        }

        const baseURL = import.meta.env.VITE_API_URL;
        const res = await axios.get(`${baseURL}/api/reports/`, {
          headers: { Authorization: `Bearer ${token}` },
        });

        setReports(res.data.data || []);
      } catch (err) {
        console.error("Failed to fetch reports:", err);
        setError(
          err.response?.data?.message || "Failed to load reports. Please try again."
        );
      } finally {
        setLoading(false);
      }
    };

    fetchReports();
  }, []);

  return (
    <div className="min-h-screen bg-gray-900 text-green-400 font-mono relative overflow-x-hidden">
      {/* Background Grid */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(0,255,65,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,255,65,0.03)_1px,transparent_1px)] bg-[size:50px_50px]"></div>
      <Navbar />

      <div className="relative z-10 container mx-auto px-6 pt-28 pb-8">
        {/* Header */}
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

        {/* Reports */}
        <div className="max-w-5xl mx-auto space-y-6">
          {loading ? (
            <div className="text-center text-gray-500">Loading reports...</div>
          ) : error ? (
            <div className="text-center text-red-500">{error}</div>
          ) : reports.length === 0 ? (
            <div className="text-center text-gray-500">No past reports found.</div>
          ) : (
            reports.map((report) => {
              const createdAt = report.created_at ? new Date(report.created_at) : null;

              return (
                <div
                  key={report._id}
                  className="bg-black/40 backdrop-blur-sm border border-green-400/20 rounded-lg p-6 shadow-2xl transition-transform transform hover:scale-[1.01] hover:border-green-400/50"
                >
                  {/* Website & Tags */}
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <h2 className="text-2xl font-bold text-white mb-1">
                        {report.website}
                      </h2>
                      <p className="text-sm text-gray-500">
                        Scanned on:{" "}
                        {createdAt ? createdAt.toLocaleDateString() : "Unknown"} at{" "}
                        {createdAt ? createdAt.toLocaleTimeString() : "Unknown"}
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-2 mt-1">
                      {report.tags?.map((tag) => (
                        <span
                          key={tag}
                          className="text-xs px-2 py-1 rounded-full font-medium text-green-400 bg-green-400/10"
                        >
                          {tag.toUpperCase().replace("-", " ")}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Report Summary Section */}
                  {report.report?.parsed && (
                    <div className="text-gray-300 leading-relaxed space-y-2 mb-4">
                      {report.report.parsed.summary && (
                        <p>
                          <strong>Summary:</strong> {report.report.parsed.summary}
                        </p>
                      )}
                      {report.report.parsed.criticality && (
                        <>
                          <p>
                            <strong>Overall Criticality Level:</strong>{" "}
                            {report.report.parsed.criticality.overall_level}
                          </p>
                          {report.report.parsed.criticality.rationale && (
                            <p>
                              <strong>Rationale:</strong> {report.report.parsed.criticality.rationale}
                            </p>
                          )}
                        </>
                      )}
                      {report.report.parsed.actions && (
                        <div>
                          <strong>Recommended Actions:</strong>
                          <ul className="list-disc list-inside mt-1 space-y-1">
                            {Array.isArray(report.report.parsed.actions) ? (
                              report.report.parsed.actions.map((action, idx) => (
                                <li key={idx}>{action}</li>
                              ))
                            ) : (
                              <li>{report.report.parsed.actions}</li>
                            )}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Report Meta Section */}
                  {report.report?.meta && (
                    <div className="text-gray-300 leading-relaxed space-y-2 mb-4 p-4 bg-green-900/10 rounded-md border border-green-400/20">
                      <strong>Report Metadata:</strong>
                      <p>
                        <strong>Generated At:</strong> {report.report.meta.generated_at}
                      </p>
                      <p>
                        <strong>Scan Origin Summary:</strong> {report.report.meta.scan_origin_summary}
                      </p>
                      <p>
                        <strong>Confidence Score:</strong> {report.report.meta.confidence_score}
                      </p>
                      {report.report.meta.raw && (
                        <details className="mt-2">
                          <summary className="cursor-pointer text-green-400 hover:text-green-300">View Raw JSON</summary>
                          <pre className="mt-2 p-2 bg-black/50 rounded text-xs overflow-auto max-h-40">
                            {JSON.stringify(report.report.meta.raw, null, 2)}
                          </pre>
                        </details>
                      )}
                    </div>
                  )}

                  {/* Detailed Vulnerabilities */}
                  {report.report?.parsed?.detailed_report?.length > 0 && (
                    <div className="space-y-4">
                      <h3 className="text-xl font-semibold text-white mb-3">Detailed Vulnerabilities</h3>
                      {report.report.parsed.detailed_report.map((vul, idx) => (
                        <div
                          key={idx}
                          className="bg-green-900/20 p-4 rounded-md border border-green-400/20"
                        >
                          <h4 className="text-lg font-semibold text-white mb-2">
                            {vul.title} -{" "}
                            <span className="text-green-400">{vul.severity}</span>
                          </h4>
                          {vul.cwe_id && (
                            <p>
                              <strong>CWE ID:</strong> {vul.cwe_id}
                            </p>
                          )}
                          {vul.cve_id && vul.cve_id !== "N/A" && (
                            <p>
                              <strong>CVE ID:</strong> {vul.cve_id}
                            </p>
                          )}
                          <p>
                            <strong>Attack Vector:</strong> {vul.attack_vector}
                          </p>
                          {vul.affected_components?.length > 0 && (
                            <p>
                              <strong>Affected Components:</strong>{" "}
                              {vul.affected_components.join(", ")}
                            </p>
                          )}
                          {vul.evidence && (
                            <p>
                              <strong>Evidence:</strong> {vul.evidence}
                            </p>
                          )}
                          {vul.technical_analysis && (
                            <p>
                              <strong>Technical Analysis:</strong> {vul.technical_analysis}
                            </p>
                          )}
                          {vul.impact && (
                            <p>
                              <strong>Impact:</strong> {vul.impact}
                            </p>
                          )}
                          {vul.root_cause && (
                            <p>
                              <strong>Root Cause:</strong> {vul.root_cause}
                            </p>
                          )}
                          {vul.exploitation_scenario && (
                            <p>
                              <strong>Exploitation Scenario:</strong> {vul.exploitation_scenario}
                            </p>
                          )}
                          {vul.detection_source && (
                            <p>
                              <strong>Detection Source:</strong> {vul.detection_source}
                            </p>
                          )}
                          {vul.related_vulnerabilities?.length > 0 && (
                            <div>
                              <strong>Related Vulnerabilities:</strong>
                              <ul className="list-disc list-inside mt-1 space-y-1">
                                {vul.related_vulnerabilities.map((rel, relIdx) => (
                                  <li key={relIdx}>{rel}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                          {vul.remediation && (
                            <p>
                              <strong>Remediation:</strong> {vul.remediation}
                            </p>
                          )}
                          {vul.references?.length > 0 && (
                            <div>
                              <strong>References:</strong>
                              <ul className="list-disc list-inside mt-1 space-y-1">
                                {vul.references.map((ref, refIdx) => (
                                  <li key={refIdx}>{ref}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Error Section if Present */}
                  {report.report?.error && (
                    <div className="text-red-400 p-4 bg-red-900/20 rounded-md border border-red-400/20 mt-4">
                      <strong>Report Error:</strong> {report.report.error}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};

export default HistoryPage;