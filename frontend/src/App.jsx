import { BrowserRouter as Router, Routes, Route } from "react-router-dom";

import DomainInput from "./pages/inputPage/DomainInput";
import ReportPage from "./pages/report/ReportPage";

function App() {
  return (
    <Router>
      <Routes>
        <Route path = "/" element = {<DomainInput/>} />
        <Route path = "/report/:domainUrl" element = {<ReportPage/>} />
      </Routes>
    </Router>
  )
}

export default App