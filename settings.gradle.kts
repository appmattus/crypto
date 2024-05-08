pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        //noinspection JcenterRepositoryObsolete Just needed for Groupie
        jcenter()
        google()
        mavenCentral()
    }
}

include(":cryptohash")
include(":samples:shared")
include(":samples:androidApp")
