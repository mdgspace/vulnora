import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import "./Report.css"

const ReportPage = () => {
    const {domainUrl} = useParams()
    const url = decodeURIComponent(domainUrl)
    const [pdfUrl, setPdf] = useState(null)
    
    useEffect(() => {
    // will replace this with an api request once backend made
    setPdf("https://files.eric.ed.gov/fulltext/EJ1172284.pdf");
  }, []);

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