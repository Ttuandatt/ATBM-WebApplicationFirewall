import os

def print_tree(start_path, prefix=""):
    """Đệ quy in ra cấu trúc thư mục dưới dạng cây giống lệnh tree."""
    items = sorted(os.listdir(start_path))

    # Tên thư mục cần bỏ qua (dù ở cấp nào)
    skip_dirs = {"__pycache__", "node_modules", ".git", "venv", ".venv", ".idea"}

    # Bộ lọc danh sách hiển thị
    entries = [item for item in items if item not in skip_dirs]
    last_index = len(entries) - 1

    for index, item in enumerate(entries):
        path = os.path.join(start_path, item)

        # 🔹 Bỏ qua thư mục con cụ thể: TrainingModels/data
        if os.path.normpath(path).endswith(os.path.normpath("TrainingModels/data")):
            continue

        connector = "└─ " if index == last_index else "├─ "
        print(prefix + connector + item)

        if os.path.isdir(path):
            extension = "   " if index == last_index else "│  "
            print_tree(path, prefix + extension)

if __name__ == "__main__":
    # 🔹 Đường dẫn gốc đến project của bạn
    root_dir = r"D:\IT\ATBM-WebApplicationFirewall"

    if not os.path.exists(root_dir):
        print(f"❌ Thư mục '{root_dir}' không tồn tại.")
    else:
        print(f"{os.path.basename(root_dir)}/")
        print_tree(root_dir)
