# Default ignore patterns used by RepositoryManager

DEFAULT_IGNORE_DIRS = {
    # Version Control
    ".git", ".svn", ".hg", ".bzr", ".repo", "CVS", ".pijul",
    
    # Build/Output Artifacts
    "dist", "build", "target", "out", "bin", "obj", "public", "static",
    "__pycache__", "node_modules", "vendor", "bower_components",
    "packages", ".next", ".nuxt", ".svelte-kit", ".output", ".vercel",
    "netlify", ".netlify", ".serverless", "compiled", "deploy", "releases",
    "bundle", "bundles", "publish", "lib", "libs", ".gradle", "gradle",
    ".maven", "maven-repository", "maven", ".m2", "site-packages", "wheels",
    ".npm", ".yarn", ".pnpm-store", "jspm_packages", "bower_packages",
    "artifacts", "dists", "_build", "ebin", "deps", "priv",
    
    # Compiled Languages/Output folders
    "debug", "release", "x64", "x86", "arm64", "armeabi", "mips", "win32",
    "darwin", "linux", "gen", "generated", ".dart_tool",
    
    # Package Manager
    "node_modules", "jspm_packages", "bower_components", "vendor", "Pods",
    "Carthage", ".pub-cache", "pub-cache", "npm-packages", "packages", "pkg",
    "nuget", "paket-files", ".paket", ".nuget", "gems", "gem", "bundler",
    ".bundle", ".cargo", "cargo-target", "renv", "venv", ".renv", ".venv",
    ".poetry", ".pipenv", "pip-wheel-metadata", ".pnpm",
    
    # Environment/VMs
    ".venv", "venv", "env", ".env", "virtualenv", ".virtualenv", 
    "virtual", ".virtual", "pythonenv", ".pyenv", ".rbenv", ".jenv", ".sdkman",
    ".direnv", "node_env", "nenv", "renv", ".renv", "conda-env",
    ".tox", "poetry", ".poetry", ".pipenv", "pipenv",
    
    # Cache/Temp
    ".cache", "cache", "__cache__", "tmp", "temp", ".temp", ".tmp",
    ".next", ".nuxt", ".svelte-kit", ".parcel-cache", ".webpack",
    ".eslintcache", ".stylelintcache", ".rollup.cache", 
    "rollup.cache", ".babel-cache", ".jest-cache", ".tsbuildinfo",
    ".clangd", ".ccls-cache", ".sass-cache", ".pytest_cache", 
    ".mypy_cache", ".ruff_cache", ".tox", "pytest-cache", "jest-cache",
    ".phpunit.result.cache", ".phpcs-cache", ".phpmd-cache", 
    ".sonar", ".scannerwork", ".nyc_output", ".rush", "storybook-static",
    "coverage", ".coverage", "htmlcov", ".hypothesis",
    
    # IDE/Editor specific
    ".vscode", ".idea", ".project", ".settings", ".classpath", ".factorypath",
    ".vs", ".netbeans", "nbproject", ".eclipse", ".metadata", ".c9",
    ".history", ".ionide", ".atom", ".ensime", ".ensime_cache", ".ensime_lucene",
    ".devcontainer", ".fleet", ".theia",
    
    # OS specific
    ".Spotlight-V100", ".Trashes", "$RECYCLE.BIN", "System Volume Information", ".fseventsd",
    ".Trash-",
    
    # Logs
    "logs", "log", "crashlytics",
    
    # Test/Examples/Docs
    "tests", "test", "spec", "__tests__", "cypress", "__mocks__", "mocks",
    "examples", "example", "__fixtures__", "fixtures", "docs", "doc",
    "documentation", "jsdoc", "apidoc", "typedoc", "javadoc", "rdoc",
    "godoc", "man", "manual", "guides", "reference", ".storybook", "stories",
    
    # Database and storage
    "data", ".data", "database", "db", "databases", ".db", "sqlite",
    "migrations", "seeds", "fixtures", "dumps", "backup", "backups",
    "sql", "mongodb", "postgres", "mysql", "redis", "neo4j", "cassandra",
    "dynamodb", "couchdb", "leveldb", "elasticsearch", "solr", "localstack",
    
    # Framework specific
    # Angular
    "ngcc", ".angular", "angular", ".ng_build", ".ng_pkg_build",
    
    # React and React Native
    "react-native-packager-cache-", ".expo", ".expo-shared", "expo-cache",
    
    # Flutter/Dart
    ".dart_tool", ".pub", ".flutter-plugins", ".flutter-plugins-dependencies",
    
    # Python
    "__pypackages__", "Lib", "Scripts", "Include",
    
    # Java
    "classes", "META-INF", "WEB-INF",
    
    # Swift/iOS
    "Pods", "Carthage", "DerivedData", "xcuserdata",
    
    # Ruby
    ".bundle", "vendor/bundle", "lib/bundler", "pkg", "rdoc",
    
    # Go
    "pkg", "bin", "vendor", ".glide", "glide", ".vendor-new",
    
    # Rust
    "target", "rls",
    
    # Vue
    ".nuxt", ".vue-static", "vue-ssr",
    
    # Svelte
    ".svelte-kit", ".svelte", "__sapper__", "svelte-kit",
    
    # Next.js
    ".next", ".vercel",
    
    # Ionic
    "www", ".ionic", "plugins", "platforms",
    
    # Xamarin
    "bin", "obj", "packages", ".vs", "bld",
    
    # Framework7
    "framework7", "f7-components",
    
    # Laravel
    "bootstrap/cache", "storage", "vendor",
    
    # Django
    "migrations", "staticfiles", "__pycache__", ".pytest_cache",
    
    # Spring Boot
    "target", "build", ".gradle", "gradle", ".mvn",
    
    # Express.js/Node.js
    "node_modules",
    
    # ASP.NET
    "bin", "obj", "packages", ".vs", "bld", "artifacts",
    
    # Media/Assets/Static files
    "assets", "static", "media", "img", "images", "icons", "fonts",
    "videos", "audio", "sounds", "music", "animations", "uploads",
    "downloads", "i18n", "locale", "locales", "l10n", "translations",
    "stylesheets", "styles", "css", "scss", "sass", "less", "styl",
    
    # UI/UX Design
    "design", "designs", "mockups", "wireframes", "prototypes", "sketch",
    "figma", "xd", "zeplin", "invision",
    
    # Generated docs
    "api-docs", "apidocs", "swagger", "openapi", "graphql-schema",
    "redoc",
    
    # Script utilities
    "scripts", "tools", "utils", "utilities", "bin", "cli", "tasks",
    
    # Other common exclusions
    "coverage", "sonar", "security-reports", "reports", "report", ".sonarlint", ".scannerwork",
    "licenses", "license", "legal", ".legal",
    "third-party", "third_party", "3rdparty", "vendors", "dist-artifacts",
    
    # Temporary backups
    "backup",".flashrank_cache", "alembic","surf_new_backend.egg-info"
}

DEFAULT_IGNORE_FILE_PATTERNS = {
    # Version Control
    "*.orig", "*.rej",
    
    # Compiled files
    "*.pyc", "*.o", "*.so", "*.dll", "*.exe", "*.pdb", "*.a", "*.lib", 
    "*.dylib", "*.pyd", "*.jar", "*.war", "*.ear", "*.app", "*.apk", 
    "*.ipa", "*.aab", "*.aar", "*.xap", "*.map", "*.min.js", "*.min.css",
    "*.class",
    
    # Package Manager lock files
    "poetry.lock", "Pipfile.lock", "yarn.lock", "package-lock.json", 
    "pnpm-lock.yaml", "composer.lock", "Gemfile.lock", "go.sum", "Cargo.lock",
    "mix.lock", "bun.lockb", "coffee-script.lock","uv.lock",
    
    # Environment/Version files
    ".env", ".env.*",
    ".python-version", ".node-version", ".ruby-version", ".nvmrc",
    "pyvenv.cfg",
    
    # IDE/Editor specific
    "*.suo", "*.user", "*.userosscache", "*.dbmdl", "*.dbproj.user",
    "*.sublime-workspace", "*.sublime-project", "*.komodoproject",
    "*.swp", "*.swo", "*.code-workspace", "*.iml", "*.ipr", "*.iws",
    "*.bak", "*.vsix",
    
    # OS specific
    ".DS_Store", "Thumbs.db", ".directory", ".AppleDouble", ".LSOverride",
    "ehthumbs.db", "ehthumbs_vista.db", "Desktop.ini", ".apdisk", 
    "*.lnk", "NTUSER.DAT*", "ntuser.dat*", "ntuser.ini",
    "IconCache.db", "IconCache.db.lock", "thumbcache_*.db",
    
    # Logs
    "*.log", "npm-debug.log*", "yarn-debug.log*", "yarn-error.log*", 
    "pnpm-debug.log*", "lerna-debug.log*", "debug.log",
    "crashlytics-build.properties", "com_crashlytics_export_strings.xml",
    
    # Mobile
    "*.xcworkspace",
    
    # Documentation
    "README.md",
    "CHANGELOG*", "CHANGES*", "NEWS*", "CONTRIBUTING*", "AUTHORS*",
    
    # Temporary backups
    "*~", "*.bak", "*.backup", "*.tmp", "*.temp", ".#*", "#*#", "*.save",
    
    # Archives and compressed files
    "*.zip", "*.tar", "*.tar.gz", "*.tgz", "*.tar.bz2", "*.tar.xz",
    "*.7z", "*.rar", "*.gz", "*.bz2", "*.xz", "*.z", "*.lz", "*.lzma",
    "*.lzo", "*.rz", "*.lz4", "*.zst",
    
    # Python Specific
    "celerybeat-schedule",
    
    # Vue Specific
    "vue-ssr-client-manifest.json",
    "vue-ssr-server-bundle.json",
    
    # Next.js Specific
    "next-env.d.ts",
    "next.config.js",
    
    # Maven Specific
    "mvnw",
    "mvnw.cmd",
    
    # Test/Fixture Files (Common Patterns)
    "*.spec.ts",
    "*.fixtures.ts",
    "*.test.js", "*.spec.js", "*.test.jsx", "*.spec.jsx",
    "*.test.py", "test_*.py", "*_test.py",
}
