
import './App.css';
import Navbar from './Components/Navbar/Navbar';
import { BrowserRouter,Routes,Route } from 'react-router-dom';
import Shop from './Pages/Shop';
import ShopCategory from './Pages/ShopCategory';
import Product from './Pages/Product';
import LoginSignup from './Pages/LoginSignup';
import Cart from './Pages/Cart';
import Footer from './Components/Footer/Footer';
import onepiece_banner from './Components/Assets/banner_onepiece.png'
import naruto_banner from './Components/Assets/banner_naruto.png'
import bleach_banner from './Components/Assets/banner_bleach.png'
import ProfileUpdate from './Pages/ProfileUpdate';

function App() {
  return (
    <div>
      <BrowserRouter>
      <Navbar/>
      <Routes>
        <Route path='/' element={<Shop/>} />
        <Route path='/onepiece' element={<ShopCategory banner={onepiece_banner} category="onepiece"/>} />
        <Route path='/naruto' element={<ShopCategory banner={naruto_banner} category="naruto"/>} />
        <Route path='/bleach' element={<ShopCategory banner={bleach_banner} category="bleach"/>} />
        <Route path='product' element={<Product/>}>
          <Route path=':productId' element={<Product/>}/>
        </Route>
        <Route path='/cart' element={<Cart/>}/>
        <Route path='/login' element={<LoginSignup/>}/>
        <Route path='/profileupdate' element={<ProfileUpdate/>} />
      </Routes>
      <Footer/>
      </BrowserRouter>
    </div>
  );
}

export default App;
