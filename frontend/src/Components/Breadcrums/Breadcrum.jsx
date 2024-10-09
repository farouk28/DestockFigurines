import React from 'react';
import './Breadcrum.css'
import arrow_icon from '../Assets/breadcrum_arrow.png'

const Breadcrum = (props) => {
    const {product} = props;
    return (
        <div className='breadcrum'>
            Home <img src={arrow_icon} alt="Home" /> SHOP <img src={arrow_icon} alt="Shop" /> {product.category} <img src={arrow_icon} alt={product.category} /> {product.name}
        </div>
    );
}

export default Breadcrum;
