# Open the Base64 blob and read its content
with open("fhZip.txt", "r") as file:
    base64Content = file.read().strip()

# Open the HTML template and read its content
with open("calendar.html", "r") as file:
    template = file.read()

# Replace the placeholder with the actual Base64 content
templateWithContent = template.replace("var binary = '';", f"var binary = '{base64Content}';")

# Write the modified template with the Base64 content back to a new file
with open("fhZip.html", "w") as file:
    file.write(templateWithContent)

