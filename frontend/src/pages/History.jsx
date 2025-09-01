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

        const res = await axios.get(`http://localhost:8081/api/reports/`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
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
          {loading ? (
            <div className="text-center text-gray-500">Loading reports...</div>
          ) : error ? (
            <div className="text-center text-red-500">{error}</div>
          ) : reports.length === 0 ? (
            <div className="text-center text-gray-500">No past reports found.</div>
          ) : (
            <div className="space-y-6">
              {reports.map((report) => (
                <div
                  key={report._id}
                  className="bg-black/40 backdrop-blur-sm border border-green-400/20 rounded-lg p-6 shadow-2xl transition-transform transform hover:scale-[1.01] hover:border-green-400/50"
                >
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <h2 className="text-2xl font-bold text-white mb-1">
                        {report.website}
                      </h2>
                      <p className="text-sm text-gray-500">
                        Scanned on:{" "}
                        {new Date(report.createdAt).toLocaleDateString()} at{" "}
                        {new Date(report.createdAt).toLocaleTimeString()}
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

                  {/* Render report details safely */}
                  <div className="text-gray-300 leading-relaxed space-y-2">
                    {report.report?.summary && (
                      <p>
                        <strong>Summary:</strong> {report.report.summary}
                      </p>
                    )}

                    {report.report?.criticality && (
                      <p>
                        <strong>Criticality:</strong>{" "}
                        {typeof report.report.criticality === "string"
                          ? report.report.criticality
                          : JSON.stringify(report.report.criticality)}
                      </p>
                    )}

                    {report.report?.actions && (
                      <p>
                        <strong>Actions:</strong>{" "}
                        {typeof report.report.actions === "string"
                          ? report.report.actions
                          : JSON.stringify(report.report.actions)}
                      </p>
                    )}
                  </div>
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
