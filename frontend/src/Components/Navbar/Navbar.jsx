import React, { useState, useEffect, useRef, useContext } from 'react';
import axios from 'axios';
import './Navbar.css';
import logo from '../Assets/naruto_logo.png';
import cart_icon from '../Assets/cart_icon.png';
import { Link } from 'react-router-dom';
import { ShopContext } from '../../Context/ShopContext';
import nav_dropdown from '../Assets/nav_dropdown.png';

const Navbar = () => {
  const [username, setUsername] = useState('');
  const [menu, setMenu] = useState("shop");
  const { getTotalCartItems } = useContext(ShopContext);
  const menuRef = useRef();

  useEffect(() => {
    axios.get('/users:_id')
      .then(response => {
        console.log('API response:', response.data); // Add this line
        setUsername(response.data.name);
      })
      .catch(error => {
        console.error(error);
      });
  }, []);

  const dropdown_toggle = (e) => {
    menuRef.current.classList.toggle('nav-menu-visible');
    e.target.classList.toggle('open');
  }

  return (
    <div className='navbar'>
      <div className='nav-logo'>
        <img src={logo} alt="Logo" />
        <p>DestockFigurines</p>
      </div>
      <img className='nav-dropdown' onClick={dropdown_toggle} src={nav_dropdown} alt="dropdown the menu" />
      <ul ref={menuRef} className='nav-menu'>
        <li onClick={() => { setMenu("shop") }}><Link style={{ textDecoration: 'none' }} to='/'>Shop</Link>{menu === "shop" ? <hr /> : <></>}</li>
        <li onClick={() => { setMenu("onepiece") }}><Link style={{ textDecoration: 'none' }} to='/onepiece'>One Piece</Link>{menu === "onepiece" ? <hr /> : <></>}</li>
        <li onClick={() => { setMenu("naruto") }}><Link style={{ textDecoration: 'none' }} to='/naruto'>Naruto</Link>{menu === "naruto" ? <hr /> : <></>}</li>
        <li onClick={() => { setMenu("bleach") }}><Link style={{ textDecoration: 'none' }} to='/bleach'>Bleach</Link>{menu === "bleach" ? <hr /> : <></>}</li>
      </ul>
      <div className='nav-login-cart'>
        {localStorage.getItem('auth-token')
          ? (
            <div className='user-menu'>
                <span>Welcome, {username}!</span> {/* Display the username */}
                <p className='nav-dropdown-2' onClick={dropdown_toggle}>v</p>
                <div>
                    <ul ref={menuRef} className='nav-menu-2'>
                        <li onClick={() => { setMenu("profileupdate") }}><Link style={{ textDecoration: 'none' }} to='/profileupdate'>Parameter</Link>{menu === "profileupdate" ? <hr /> : <></>}</li>
                        <li className='pointer' onClick={() => { localStorage.removeItem('auth-token'); window.location.replace('/') }}>Logout</li>
                    </ul>
                </div>
            </div>
          )
          : (
            <Link to='/login'>
              <button>Login</button>
            </Link>
          )}
        <Link to='/cart'><img src={cart_icon} alt="go to Cart" /></Link>
        <div className='nav-cart-count'>{getTotalCartItems()}</div>
      </div>
    </div>
  )
}

export default Navbar;