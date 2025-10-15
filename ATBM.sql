
DROP DATABASE IF EXISTS BookStoreDB;
CREATE DATABASE BookStoreDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE BookStoreDB;

-- =============================================
-- 1. Category
-- =============================================
CREATE TABLE Category (
    idCategory INT AUTO_INCREMENT PRIMARY KEY,
    nameCategory VARCHAR(100) NOT NULL
);

INSERT INTO Category (nameCategory)
VALUES 
('Fiction'),
('Science'),
('Technology'),
('Children'),
('History');

-- =============================================
-- 2. Suppliers
-- =============================================
CREATE TABLE Suppliers (
    idSupplier INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    phone VARCHAR(20),
    email VARCHAR(100),
    address VARCHAR(200)
);

INSERT INTO Suppliers (name, phone, email, address)
VALUES
('ABC Books', '0905123456', 'abcbooks@gmail.com', '123 Nguyen Trai, HCM'),
('Global Publisher', '0912345678', 'global@pub.com', '45 Le Loi, Hanoi'),
('Knowledge Co.', '0988777666', 'info@knowledge.vn', '56 Tran Hung Dao, Da Nang');

-- =============================================
-- 3. Books
-- =============================================
CREATE TABLE Books (
    idBook INT AUTO_INCREMENT PRIMARY KEY,
    nameBook VARCHAR(150) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    stockQuantity INT DEFAULT 0,
    imgBook VARCHAR(255),
    idCategory INT,
    idSupplier INT,
    FOREIGN KEY (idCategory) REFERENCES Category(idCategory) ON DELETE SET NULL ON UPDATE CASCADE,
    FOREIGN KEY (idSupplier) REFERENCES Suppliers(idSupplier) ON DELETE SET NULL ON UPDATE CASCADE
);

INSERT INTO Books (nameBook, price, stockQuantity, imgBook, idCategory, idSupplier)
VALUES
('The Great Gatsby', 120000, 50, 'great_gatsby.jpg', 1, 1),
('Physics for Everyone', 150000, 30, 'physics.jpg', 2, 2),
('Learn Python', 200000, 40, 'python.jpg', 3, 3),
('Fairy Tales', 90000, 60, 'fairy_tales.jpg', 4, 1),
('World War II', 180000, 25, 'ww2.jpg', 5, 2);

-- =============================================
-- 4. Users
-- =============================================
CREATE TABLE Users (
    idUser INT AUTO_INCREMENT PRIMARY KEY,
    nameUser VARCHAR(100) NOT NULL,
    password VARCHAR(100) NOT NULL,
    phone VARCHAR(20),
    email VARCHAR(100),
    address VARCHAR(200)
);

INSERT INTO Users (nameUser, password, phone, email, address)
VALUES
('Nguyen Van A', '123456', '0909000001', 'a@gmail.com', 'HCM'),
('Tran Thi B', 'abcdef', '0909000002', 'b@gmail.com', 'Hanoi');

-- =============================================
-- 5. Employees
-- =============================================
CREATE TABLE Employees (
    idEmp INT AUTO_INCREMENT PRIMARY KEY,
    nameUser VARCHAR(100) NOT NULL,
    password VARCHAR(100) NOT NULL,
    phone VARCHAR(20),
    email VARCHAR(100),
    role VARCHAR(50)
);

INSERT INTO Employees (nameUser, password, phone, email, role)
VALUES
('Admin', 'admin123', '0909111222', 'admin@bookstore.com', 'Manager'),
('Linh', 'linhpass', '0909222333', 'linh@bookstore.com', 'Cashier');

-- =============================================
-- 6. Orders
-- =============================================
CREATE TABLE Orders (
    idOrder INT AUTO_INCREMENT PRIMARY KEY,
    idUser INT,
    date DATETIME DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50),
    totalAmount DECIMAL(10,2),
    FOREIGN KEY (idUser) REFERENCES Users(idUser) ON DELETE SET NULL ON UPDATE CASCADE
);

INSERT INTO Orders (idUser, status, totalAmount)
VALUES
(1, 'Completed', 320000),
(2, 'Pending', 150000);

-- =============================================
-- 7. OrderItems
-- =============================================
CREATE TABLE OrderItems (
    idOrder INT,
    idBook INT,
    quantity INT DEFAULT 1,
    untilPrice DECIMAL(10,2),
    PRIMARY KEY (idOrder, idBook),
    FOREIGN KEY (idOrder) REFERENCES Orders(idOrder) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (idBook) REFERENCES Books(idBook) ON DELETE CASCADE ON UPDATE CASCADE
);

INSERT INTO OrderItems (idOrder, idBook, quantity, untilPrice)
VALUES
(1, 1, 2, 240000),
(1, 3, 1, 200000),
(2, 4, 1, 90000);

-- =============================================
-- 8. Receipt
-- =============================================
CREATE TABLE Receipt (
    idReceipt INT AUTO_INCREMENT PRIMARY KEY,
    idEmp INT,
    idSupplier INT,
    date DATETIME DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50),
    totalAmount DECIMAL(10,2),
    FOREIGN KEY (idEmp) REFERENCES Employees(idEmp) ON DELETE SET NULL ON UPDATE CASCADE,
    FOREIGN KEY (idSupplier) REFERENCES Suppliers(idSupplier) ON DELETE SET NULL ON UPDATE CASCADE
);

INSERT INTO Receipt (idEmp, idSupplier, status, totalAmount)
VALUES
(1, 1, 'Received', 500000),
(2, 2, 'Pending', 300000);

-- =============================================
-- 9. ReceiptItems
-- =============================================
CREATE TABLE ReceiptItems (
    idReceipt INT,
    idBook INT,
    quantity INT,
    discount DECIMAL(5,2) DEFAULT 0,
    PRIMARY KEY (idReceipt, idBook),
    FOREIGN KEY (idReceipt) REFERENCES Receipt(idReceipt) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (idBook) REFERENCES Books(idBook) ON DELETE CASCADE ON UPDATE CASCADE
);

INSERT INTO ReceiptItems (idReceipt, idBook, quantity, discount)
VALUES
(1, 2, 10, 5.00),
(1, 3, 5, 0),
(2, 4, 20, 10.00);
