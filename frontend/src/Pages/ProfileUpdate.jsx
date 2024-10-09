import React, { useState } from "react";
import "./CSS/ProfileUpdate.css";

const ProfileUpdate = () => {
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
    newPassword: "",
    confirmPassword: "",
  });

  const changeHandler = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const updateProfile = async () => {
    console.log("Mise à jour du profil", formData);
    let responseData;
    await fetch("http://localhost:4000/profileupdate", {
      method: "PUT",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(formData),
    })
      .then((response) => response.json())
      .then((data) => (responseData = data));

    if (responseData.success) {
      alert("Profil mis à jour avec succès");
    } else {
      alert(responseData.errors);
    }
  };

  return (
    <div className="profileupdate">
      <div className="profileupdate-container">
        <h1>Mise à jour du profil</h1>
        <div className="profileupdate-fields">
          <input
            name="username"
            value={formData.username}
            onChange={changeHandler}
            type="text"
            placeholder="Nom"
          />
          <input
            name="email"
            value={formData.email}
            onChange={changeHandler}
            type="email"
            placeholder="Adresse e-mail"
          />
          <input
            name="password"
            value={formData.password}
            onChange={changeHandler}
            type="password"
            placeholder="Mot de passe actuel"
          />
          <input
            name="newPassword"
            value={formData.newPassword}
            onChange={changeHandler}
            type="password"
            placeholder="Nouveau mot de passe"
          />
          <input
            name="confirmPassword"
            value={formData.confirmPassword}
            onChange={changeHandler}
            type="password"
            placeholder="Confirmer le nouveau mot de passe"
          />
        </div>
        <button onClick={updateProfile}>Mettre à jour le profil</button>
      </div>
    </div>
  );
};

export default ProfileUpdate;