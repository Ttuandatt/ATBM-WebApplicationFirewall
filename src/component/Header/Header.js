import React, { useState } from "react";
import { Search, Bell, ShoppingCart, User } from "lucide-react";
import LoginPopup from "./LoginPopup";

export default function Header() {
  const [showPopup, setShowPopup] = useState(false);
  return (
    <header className="w-full">
      {/* Banner trên cùng */}
      <div
        style={{ display: "flex", justifyContent: "center" }}
        className="bg-red-600 text-white flex justify-between items-center px-4 py-2 text-sm font-medium "
      >
        <div className="flex items-center gap-4">
          <img
            src="https://cdn0.fahasa.com/skin/frontend/base/default/images/logo.png"
            alt="Fahasa Logo"
            className="h-6"
          />
          <img
            src="https://cdn0.fahasa.com/media/wysiwyg/Thang-10-2024/SBOOKS_logo_310x210.png"
            alt="SBooks"
            className="h-6"
          />
        </div>
        <div className="flex items-center gap-2">
          <img src="https://cdn1.fahasa.com/media/wysiwyg/Thang-10-2025/SBOOKS_KC_Resize_1263x60.png"></img>
        </div>
      </div>

      {/* Thanh tìm kiếm */}
      <div className="flex items-center justify-between bg-white shadow px-6 py-3">
        {/* Logo */}
        <div className="flex items-center gap-2">
          <img
            src="https://cdn0.fahasa.com/skin/frontend/base/default/images/logo.png"
            alt="Fahasa"
            className="h-10"
          />
          <span className="text-2xl font-bold text-red-600">Fahasa.com</span>
        </div>

        {/* Ô tìm kiếm */}
        <div className="flex items-center w-1/2 border border-red-600 rounded overflow-hidden">
          <input
            type="text"
            placeholder="Tìm kiếm sản phẩm..."
            className="flex-grow px-4 py-2 outline-none text-sm"
          />
          <button className="bg-red-600 px-4 py-2 text-white">
            <Search size={20} />
          </button>
        </div>

        {/* Icon bên phải */}
        <div className="flex items-center gap-6 text-sm text-gray-700">
          <div className="flex flex-col items-center cursor-pointer hover:text-red-600">
            <Bell size={20} />
            <span>Thông Báo</span>
          </div>
          <div className="flex flex-col items-center cursor-pointer hover:text-red-600">
            <ShoppingCart size={20} />
            <span>Giỏ Hàng</span>
          </div>
          {/* Tài khoản */}
          <div
            className="flex flex-col items-center cursor-pointer hover:text-red-600 relative"
            onClick={() => setShowPopup(!showPopup)}
          >
            <User size={20} />
            <span>Tài Khoản</span>

            {/* Popup đăng nhập */}
            {showPopup && <LoginPopup onClose={() => setShowPopup(false)} />}
          </div>

          {/* Cờ Việt Nam */}
          <div className="flex items-center gap-1 cursor-pointer">
            <img
              src="https://flagcdn.com/w20/vn.png"
              alt="Vietnam flag"
              className="w-5 h-4 rounded"
            />
            <select className="text-sm border-none bg-transparent focus:outline-none cursor-pointer">
              <option>VN</option>
              <option>EN</option>
            </select>
          </div>
        </div>
      </div>
    </header>
  );
}
