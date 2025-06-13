import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import Select from "react-select";
import "./inputPage.css";
import axios from "axios";

const DomainInput = () => {
  const navigate = useNavigate();
  const [domainUrl, setUrl] = useState("");
  const [attack, setAttack] = useState([]);
  const [attackOptions, setAttackOptions] = useState([]);
  const backendUrl = import.meta.env.VITE_BACKEND_URL

  useEffect(() => {
    const fetchAttacks = async () => {
      try {
        const response = await axios.get(backendUrl + "/api/attacks");
        console.log(response);
        
        const attackObj = response.data.attacks;
        if (!attackObj) {
         console.error("No attacks data found in response");
         return;  
        }
        const availAttacks = Object.values(attackObj)

        const attacks = availAttacks.map((option) => ({
          value: option,
          label: option,
        }));

        attacks.push({ value: "All", label: "All" });

        setAttackOptions(attacks);
      } catch (error) {
        console.error("Error fetching attack types:", error);
      }
    };

    fetchAttacks();
  }, []);

  const handleSelection = (selection) => {
    if (!selection) return;

    const isAll = selection.find((opt) => opt.value === "All");
    if (isAll) {
      setAttack(isAll);
    } else {
      setAttack(selection);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await axios.post(backendUrl + "/api/scan", {
        domain: domainUrl,
        attacks: attack.map((a) => a.value),
      });
      navigate(`/report/${encodeURIComponent(domainUrl)}`);
    } catch (error) {
      console.error("Error occurred while scanning", error);
    }
  };

  return (
    <div className="container">
      <h1 className="title">Vulnora</h1>
      <form onSubmit={handleSubmit}>
        <input
          className="inputUrl"
          type="url"
          value={domainUrl}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="Enter Domain Url here ..."
          required
        />
        <Select
          isMulti
          options={attackOptions}
          value={attack}
          onChange={handleSelection}
          className="selections"
          placeholder="Select Attack Type"
          styles={{
            control: (base) => ({
              ...base,
              minHeight: 53,
              borderRadius: "8px",
            }),
          }}
        />
        <button type="submit" className="button">
          Submit
        </button>
      </form>
    </div>
  );
};

export default DomainInput;
