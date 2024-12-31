function attemptLogin() {
    console.log("Attempting login...");
    
    const username = textUsername.text.trim();
    const password = textPassword.text.trim();

    // Check for both fields empty
    if (username === "" && password === "") {
        console.log("Both username and password fields are empty.");
        showPopup("Please enter both username and password.", false);
        textUsername.forceActiveFocus(); // Default focus on the username field
        return;
    }

    // Check for password empty
    if (password === "") {
        console.log("Password field is empty.");
        showPopup("Please enter a password.", false);
        textPassword.forceActiveFocus();
        return;
    }

    // Check for username empty
    if (username === "") {
        console.log("Username field is empty.");
        showPopup("Please enter a username.", false);
        textUsername.forceActiveFocus();
        return;
    }

    if (password !== "") {
        console.log("Password field is not empty.");
        if(!sessionview.verify_password(password)){
            textPassword.forceActiveFocus();
            return;
        }
        
    }

    if (username !== "") {
        console.log("Username field is not empty.");
        if(!sessionview.verify_username(username)){
            textUsername.forceActiveFocus();
            return;
        }
    }

    // Both fields filled
    console.log(`Logging in with username: ${username}`);
    sessionview.login(username, password);

    // Clear the fields after successful login
    console.log("Login successful. Clearing username and password fields.");
    textUsername.text = "";
    textPassword.text = "";
}

