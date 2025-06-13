import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import "./Report.css"
import axios from "axios";

const ReportPage = () => {
    const {domainUrl} = useParams()
    const url = decodeURIComponent(domainUrl)
    const [pdfUrl, setPdf] = useState(null)
    const backendUrl = import.meta.env.VITE_BACKEND_URL

    useEffect(() => {
        const fetchReport = async () => {
            try {
                const response = await axios.get(`${backendUrl}/api/report/${encodeURIComponent(url)}`);
                setPdf(response.data.pdf_url);
            } catch (error) {
                console.error("Error fetching report:", error);
            }
        };

        fetchReport();
    }, [url, backendUrl]);

    return (
        <div className="rep-container">
            <h1 className="title">Report Page</h1>
            {pdfUrl == null ? (
                <h2 className="loadingText">Your Report is Loading</h2>
            ) : (
                <div className="pdf-container">
                    <iframe
                        src={`${pdfUrl}`}
                        className="pdf"
                    ></iframe>
                    <a href={pdfUrl} target="_blank">
                      <button className="dwnldBtn">View PDF</button>
                   </a>
                </div>
            )}
        </div>
    );
};

export default ReportPage;