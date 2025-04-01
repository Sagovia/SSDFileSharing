const createUserValidationSchema = {
    username: {
        notEmpty: {
            errorMessage: "Username cannot be empty"
        },
        isString: {
            errorMessage: "Username must be a string"
        },
        matches: {
            options: [/^[a-zA-Z0-9]+$/],
            errorMessage: "Username can only contain letters and numbers (no spaces or special characters)"
        }
    },
    password: {
        notEmpty: {
            errorMessage: "Password cannot be empty"
        },
        isString: {
            errorMessage: "Password must be a string"
        }
    },
    email: {
        notEmpty: {
            errorMessage: "Email cannot be empty"
        },
        isEmail: {
            errorMessage: "Invalid email format"
        },
        normalizeEmail: true
    }
}

module.exports = createUserValidationSchema;