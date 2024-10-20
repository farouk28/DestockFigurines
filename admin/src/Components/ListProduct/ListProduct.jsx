import React, { useEffect, useState,useRef } from 'react';
import './ListProduct.css'
import cross_icon from '../../assets/cross_icon.png'
import edit_icon from '../../assets/edit_icon.png'

const ListProduct = () => {

    const [allproducts, setAllProducts] = useState([]);
    const [name, setName] = useState('');
    const [oldPrice, setOldPrice] = useState('');
    const [newPrice, setNewPrice] = useState('');
    const [category, setCategory] = useState('');

    const fetchInfo = async ()=>{
        await fetch('http://localhost:4000/allproducts')
        .then((res)=>res.json())
        .then((data)=>{setAllProducts(data)});
    }

    useEffect(()=>{
        fetchInfo();
    },[])

    const remove_product = async (id)=>{
        await fetch('http://localhost:4000/removeproduct',{
            method:'POST',
            headers:{
                Accept:'application/json',
                'Content-Type':'application/json',
            },
            body:JSON.stringify({id:id})
        })
        await fetchInfo();
    }

    const update_product = async (product) => {
        await fetch(`http://localhost:4000/updateproduct/${product.id}`, {
          method: 'PATCH', // Use PATCH instead of POST for updating resources
          headers: {
            Accept: 'application/json',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            name: product.name, // Send the new name
            old_price: product.oldPrice, // Send the new old price
            new_price: product.newPrice, // Send the new new price
            category: product.category, // Send the new category
          }),
        })
        .then(response => response.json())
        .then(data => console.log(data))
        .catch(error => console.error(error));
        await fetchInfo();
      };

    const menuRef = useRef();

    const dropdown_toggle = (e) =>{
        menuRef.current.classList.toggle('update-product-visible');
        e.target.classList.toggle('open');
    }

    return (
        <div className='list-product'>
            <h1>All Products List</h1>
            <div className="listproduct-format-main">
                <p>Products</p>
                <p>Title</p>
                <p>Old Price</p>
                <p>New Price</p>
                <p>Category</p>
                <p>Edit</p>
                <p>Remove</p>
            </div>
            <div className="listproduct-allproducts">
                <hr />
                {allproducts.map((product, index)=>{
                    return <>
                    <div key={index} className="listproduct-format-main listproduct-format">
                        <img src={product.image} alt="" className="listproduct-product-icon" />
                        <p>{product.name}</p>
                        <p>${product.old_price}</p>
                        <p>${product.new_price}</p>
                        <p>{product.category}</p>
                        <img onClick={dropdown_toggle} className='listuser-edit-icon dropdown' src={edit_icon} alt="" />
                        <img onClick={()=>{remove_product(product.id)}} className='listproduct-remove-icon' src={cross_icon} alt="" />
                    </div>
                    <hr />

                    <div>
                    <div ref={menuRef} className='update-product'>
      <div className="updateproduct-format-main">
        <p>Name</p>
        <p>Old Price</p>
        <p>New Price</p>
        <p>Category</p>
        <p>Send</p>
      </div>
      <div className="updateproduct-allproducts">
      <hr />
          <div key={index} className="updateproduct-format-main updateproduct-format">
            <input type="text" value={name} onChange={(e) => setName(e.target.value)} />
            <input type="text" value={oldPrice} onChange={(e) => setOldPrice(e.target.value)} />
            <input type="text" value={newPrice} onChange={(e) => setNewPrice(e.target.value)} />
            <input type="text" value={category} onChange={(e) => setCategory(e.target.value)} />
            <button onClick={() => { update_product({ id: product.id, name, oldPrice, newPrice, category }) }}>Send</button>
          </div>
          <hr />
        </div>
    </div>
    </div>
                    </>
                })}
            </div>
        </div>
    );
}

export default ListProduct;
