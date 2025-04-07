const createFolderValidationSchema = {
    password: {
        optional: {
            options: { nullable: true }, // Allows password to be missing (Files don't need passwords always)
        },
        notEmpty: {
            errorMessage: "Password cannot be empty"
        },
        isString: {
            errorMessage: "Password must be a string"
        }
    },
    name: {
        notEmpty: {
            errorMessage: "Folder name cannot be empty"
        },
        isString: {
            errorMessage: "Folder name must be a string"
        }
    },
    isPrivate: {
        customSanitizer: {
            options: (value) => value === "true", // Convert "true" to true, otherwise return false
        },
        isBoolean: {
            errorMessage: "isPrivate must be a boolean",
        },
    },
}

module.exports = createFolderValidationSchema;