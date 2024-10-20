import React, { useEffect, useState, useRef } from 'react';
import './UserList.css'
import cross_icon from '../../assets/cross_icon.png'
import edit_icon from '../../assets/edit_icon.png'

const UserList = () => {

    const [allusers, setAllUsers] = useState([]);
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');

    const fetchInfo = async ()=>{
        await fetch('http://localhost:4000/allusers')
        .then((res)=>res.json())
        .then((data)=>{setAllUsers(data)});
    }

    useEffect(()=>{
        fetchInfo();
    },[])

    const remove_user = async (_id)=>{
        await fetch('http://localhost:4000/removeuser',{
            method:'POST',
            headers:{
                Accept:'application/json',
                'Content-Type':'application/json',
            },
            body:JSON.stringify({id:_id})
        })
        await fetchInfo();
    }

    const update_user = async (user) => {
        await fetch('http://localhost:4000/updateuser', {
          method: 'PATCH', // Use PATCH instead of POST for updating resources
          headers: {
            Accept: 'application/json',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            id: user._id, // Send the user ID in the request body
            name: name, // Send the new name
            email: email, // Send the new email
            password: password, // Send the new password
          }),
        })
        .then(response => response.json())
        .then(data => console.log(data))
        .catch(error => console.error(error));
        await fetchInfo('user updated');
      };

    const menuRef = useRef();

    const dropdown_toggle = (e) =>{
        menuRef.current.classList.toggle('update-user-visible');
        e.target.classList.toggle('open');
    }

    const handleChange = (e) => {
        switch (e.target.name) {
          case 'name':
            setName(e.target.value);
            break;
          case 'email':
            setEmail(e.target.value);
            break;
          case 'password':
            setPassword(e.target.value);
            break;
          default:
            break;
        }
      };

    return (
        <div>
            <div className='list-user'>
            <h1>All Users List</h1>
            <div className="listuser-format-main">
                <p>Name</p>
                <p>Email</p>
                <p>Date</p>
                <p>Edit</p>
                <p>Remove</p>
            </div>
            <div className="listuser-allusers">
                <hr />
                {allusers.map((user, index)=>{
                    return <>
                    <div key={index} className="listuser-format-main listuser-format">
                        <p>{user.name}</p>
                        <p>{user.email}</p>
                        <p>{user.date}</p>
                        <img onClick={dropdown_toggle} className='listuser-edit-icon dropdown' src={edit_icon} alt="" />
                        <img onClick={()=>{remove_user(user._id)}} className='listuser-remove-icon' src={cross_icon} alt="" />
                    </div>
                    <hr />

                    <div>
        <div ref={menuRef} className='update-user'>
        <div className="updateuser-format-main">
            <p>Name</p>
            <p>Email</p>
            <p>Password</p>
            <p>Send</p>
        </div>
        <div className="updateuser-allusers">
            <hr />
                <div key={index} className="updateuser-format-main updateuser-format">
                    <input type="text" name="name" value={name} onChange={handleChange} />
                    <input type="email" name="email" value={email} onChange={handleChange} />
                    <input type="password" name="password" value={password} onChange={handleChange} />
                    <button onClick={() => { update_user({ _id: user._id, name, email, password }) }}>Send</button>                </div>
                <hr />
        </div>
    </div>
    </div>

                    </>
                })}
            </div>
        </div>
        </div>
    );
}

export default UserList;
