import { useState } from "react";

export default function LoginPopup({ onClose }) {
  const [isLogin, setIsLogin] = useState(true);

  return (
    <div
      className="fixed inset-0 bg-black/40 flex items-center justify-center z-50"
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="bg-white w-96 rounded-xl shadow-lg p-6 relative animate-fadeIn"
      >
        {/* Nút đóng */}
        <button
          onClick={onClose}
          className="absolute top-3 right-3 text-gray-400 hover:text-gray-600"
        >
          ✕
        </button>

        {/* Tabs */}
        <div className="flex border-b mb-4">
          <button
            onClick={() => setIsLogin(true)}
            className={`flex-1 text-center pb-2 font-medium ${
              isLogin
                ? "text-red-600 border-b-2 border-red-600"
                : "text-gray-600"
            }`}
          >
            Đăng nhập
          </button>
          <button
            onClick={() => setIsLogin(false)}
            className={`flex-1 text-center pb-2 font-medium ${
              !isLogin
                ? "text-red-600 border-b-2 border-red-600"
                : "text-gray-600"
            }`}
          >
            Đăng ký
          </button>
        </div>

        {/* Nội dung form */}
        {isLogin ? (
          // FORM ĐĂNG NHẬP
          <form className="flex flex-col gap-3">
            <div>
              <label className="text-sm text-gray-700">
                Số điện thoại/Email
              </label>
              <input
                type="text"
                placeholder="Nhập số điện thoại hoặc email"
                className="w-full border rounded px-3 py-2 mt-1 focus:outline-none focus:ring-1 focus:ring-blue-400"
              />
            </div>
            <div>
              <label className="text-sm text-gray-700">Mật khẩu</label>
              <input
                type="password"
                placeholder="Nhập mật khẩu"
                className="w-full border rounded px-3 py-2 mt-1 focus:outline-none focus:ring-1 focus:ring-blue-400"
              />
              <a href="#" className="text-red-600 text-sm float-right mt-1">
                Quên mật khẩu?
              </a>
            </div>
            <button
              type="submit"
              className="bg-gray-300 text-white py-2 rounded mt-3 hover:bg-red-600 hover:text-white transition"
            >
              Đăng nhập
            </button>
            <button
              type="button"
              onClick={onClose}
              className="border border-red-500 text-red-600 py-2 rounded mt-2 hover:bg-red-50"
            >
              Bỏ qua
            </button>
          </form>
        ) : (
          <form className="flex flex-col gap-3">
            {/* Số điện thoại */}
            <div>
              <label className="text-sm text-gray-700">Số điện thoại</label>
              <input
                type="text"
                placeholder="Nhập số điện thoại"
                className="w-full border rounded px-3 py-2 mt-1 focus:outline-none focus:ring-1 focus:ring-blue-400"
              />
            </div>

            {/* OTP Method */}
            <div>
              <label className="text-sm text-gray-700">
                Chọn phương thức xác minh OTP
              </label>
              <div className="flex gap-3 mt-2">
                <label className="flex items-center border rounded px-3 py-2 w-1/2 cursor-pointer hover:border-blue-400">
                  <input
                    type="radio"
                    name="otp"
                    className="mr-2"
                    defaultChecked
                  />
                  Tin nhắn SMS
                </label>
                <label className="flex items-center border rounded px-3 py-2 w-1/2 cursor-pointer hover:border-blue-400">
                  <input type="radio" name="otp" className="mr-2" />
                  Zalo ZNS
                </label>
              </div>
            </div>

            {/* Mã OTP */}
            <div>
              <label className="text-sm text-gray-700">Mã xác nhận OTP</label>
              <input
                type="text"
                placeholder="6 ký tự"
                maxLength="6"
                className="w-full border rounded px-3 py-2 mt-1 focus:outline-none focus:ring-1 focus:ring-blue-400"
              />
            </div>

            {/* Mật khẩu */}
            <div>
              <label className="text-sm text-gray-700">Mật khẩu</label>
              <div className="relative">
                <input
                  type="password"
                  placeholder="Nhập mật khẩu"
                  className="w-full border rounded px-3 py-2 mt-1 focus:outline-none focus:ring-1 focus:ring-blue-400"
                />
                <span className="absolute right-3 top-3 text-sm text-gray-500 cursor-pointer">
                  Hiện
                </span>
              </div>
            </div>

            {/* Nút đăng ký */}
            <button
              type="submit"
              className="bg-gray-300 text-white py-2 rounded mt-3 hover:bg-red-600 hover:text-white transition"
            >
              Đăng ký
            </button>

            {/* Bỏ qua */}
            <button
              type="button"
              onClick={onClose}
              className="border border-red-500 text-red-600 py-2 rounded mt-2 hover:bg-red-50"
            >
              Bỏ qua
            </button>

            {/* Ghi chú */}
            <p className="text-xs text-gray-500 text-center mt-2">
              Bằng việc đăng ký, bạn đã đồng ý với Fahasa về <br />
              <a href="#" className="text-blue-600 hover:underline">
                Điều khoản dịch vụ
              </a>{" "}
              &{" "}
              <a href="#" className="text-blue-600 hover:underline">
                Chính sách bảo mật
              </a>
            </p>
          </form>
        )}
      </div>
    </div>
  );
}
