import React, { useContext } from 'react';
import './ProductDisplay.css'
import star_icon from '../Assets/star_icon.png'
import star_dull_icon from '../Assets/star_dull_icon.png'
import { ShopContext } from '../../Context/ShopContext';

const ProductDisplay = (props) => {
    const {product} = props;
    const {addToCart} = useContext(ShopContext);
    return (
        <div className='productdisplay'>
            <div className="productdisplay-left">
                <div className="producdisplay-img-list">
                    <img src={product.image} alt={product.name} />
                    <img src={product.image} alt={product.name} />
                    <img src={product.image} alt={product.name} />
                    <img src={product.image} alt={product.name} />
                </div>
                <div className="productdisplay-img">
                    <img className='productdisplay-main-img' src={product.image} alt={product.name} />
                </div>
            </div>
            <div className="productdisplay-right">
                <h1>{product.name}</h1>
                <div className="productdisplay-right-stars">
                    <img src={star_icon} alt="1st star review" />
                    <img src={star_icon} alt="2nd star review" />
                    <img src={star_icon} alt="3rd star review" />
                    <img src={star_icon} alt="4th star review" />
                    <img src={star_dull_icon} alt="no 5th star review" />
                    <p>(213)</p>
                </div>
                <div className="productdisplay-right-prices">
                    <div className="productdisplay-right-price-old">${product.old_price}</div>
                    <div className="productdisplay-right-price-new">${product.new_price}</div>
                </div>
                <div className="productdisplay-right-description">
                    A small, three-dimensional statue or model of a person, animal, or object. Figurines can be made from various materials such as plastic, metal, ceramic, wood, or resin. They are often used to represent characters from fiction, or popular culture.
                </div>
                <div className="productdisplay-right-size">
                    <h1>Select Size</h1>
                    <div className="productdisplay-right-sizes">
                        <div>1/4</div>
                        <div>1/6</div>
                        <div>1/8</div>
                        <div>1/12</div>
                        <div>1/16</div>
                    </div>
                </div>
                <button onClick={()=>{addToCart(product.id)}}>ADD TO CART</button>
                <p className='productdisplay-right-category'><span>Category :</span>One Piece, Figurine</p>
                <p className='productdisplay-right-category'><span>Tags :</span>Latest</p>
            </div>
        </div>
    );
}

export default ProductDisplay;
