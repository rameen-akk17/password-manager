
def load_data():
    if os.path.exists(FILE_NAME):
        with open(FILE_NAME, "r") as file:
            return json.load(file)
    return {}

def save_data(data):
    with open(FILE_NAME, "w") as file:
        json.dump(data, file, indent=4)

def add_password():
    site = input("Enter website/app name: ")
    username = input("Enter username: ")
    password = input("Enter password: ")

    data = load_data()
    data[site] = {"username": username, "password": password}
    save_data(data)
    print("Password saved successfully.\n")

def view_password():
    site = input("Enter website/app name to view: ")
    data = load_data()

    if site in data:
        print(f"Username: {data[site]['username']}")
        print(f"Password: {data[site]['password']}\n")
    else:
        print("No saved password for that site.\n")

def main():
    while True:
        print("1. Add Password")
        print("2. View Password")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            add_password()
        elif choice == "2":
            view_password()
        elif choice == "3":
            print("Goodbye.")
            break
        else:
            print("Invalid choice.\n")

if __name__ == "__main__":
    main()
