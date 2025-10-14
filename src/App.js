import logo from "./logo.svg";
import "./App.css";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import HomePage from "./pages/HomePage/HomePage";
import Layout from "./layout/Layout";
import "./index.css";
import AdminLayout from "./layout/AdminLayout";
function App() {
  return (
    <>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout></Layout>}>
            <Route path="/" element={<HomePage></HomePage>}></Route>
          </Route>
          <Route path="admin" element={<AdminLayout></AdminLayout>}></Route>
        </Routes>
      </BrowserRouter>
    </>
  );
}

export default App;
