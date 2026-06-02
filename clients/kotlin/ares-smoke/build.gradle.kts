plugins { kotlin("jvm") }
dependencies { implementation(project(":ares-client")) }
kotlin { jvmToolchain(17) }
