return {
  name = "custom-upstream-jwt",
  fields = {
    {
      config = {
        type = "record",
        fields = {
          {
            header = {
              type = "string",
              default = "Authorization",
            },
          },
          {
            include_credential_type = {
              type = "boolean",
              default = false,
            },
          },
        },
      },
    },
  },
}
