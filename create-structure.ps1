$folders = @(
    "nexus-engine\api",
    "nexus-engine\public",
    "nexus-engine\.github\workflows"
)

$files = @(
    "nexus-engine\api\scan.py",
    "nexus-engine\api\derive.py",
    "nexus-engine\api\check.py",
    "nexus-engine\public\index.html",
    "nexus-engine\public\style.css",
    "nexus-engine\.github\workflows\expedition.yml",
    "nexus-engine\vercel.json",
    "nexus-engine\requirements.txt",
    "nexus-engine\README.md"
)

foreach ($folder in $folders) {
    New-Item -ItemType Directory -Force -Path $folder
}

foreach ($file in $files) {
    New-Item -ItemType File -Force -Path $file
}