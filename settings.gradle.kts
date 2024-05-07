pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
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
