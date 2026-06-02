plugins { kotlin("jvm") }
dependencies {
    implementation(project(":ares-client"))
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
}
kotlin { jvmToolchain(17) }
tasks.test {
    useJUnitPlatform()
    systemProperty("java.library.path",
        layout.buildDirectory.dir("native").get().asFile.absolutePath +
        File.pathSeparator + System.getProperty("java.library.path"))
}
