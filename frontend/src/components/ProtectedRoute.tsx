import { Navigate, useNavigate } from "react-router-dom";
import { jwtDecode } from "jwt-decode";
import { useState, useEffect, type ReactNode } from "react";
import { handleError } from "./utils";
import Load from "./Loader";

interface ProtectedRouteProps {
  children: ReactNode;
}

interface DecodedToken {
  exp: number;
}

function ProtectedRoute({ children }: ProtectedRouteProps): React.JSX.Element {
  const [isAuthorized, setIsAuthorized] = useState<boolean | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    auth().catch(() => setIsAuthorized(false));
  }, []);

  const auth = async (): Promise<void> => {
    const token = localStorage.getItem("ACCESS_TOKEN");
    if (!token) {
      setIsAuthorized(false);
      return;
    }
    const decoded = jwtDecode(token) as DecodedToken;
    const tokenExpiration = decoded.exp;
    const now = Date.now() / 1000;

    if (tokenExpiration < now) {
      handleError("Your session has expired. Please log in again.");
      setTimeout(() => {
        navigate("/login");
      }, 1000);
      setIsAuthorized(false);
    } else {
      setTimeout(() => {
        setIsAuthorized(true);
      }, 5000);
    }
  };

  if (isAuthorized === null) {
    return <Load />;
  }

  return isAuthorized ? <>{children}</> : <Navigate to="/login" />;
}

export default ProtectedRoute;
