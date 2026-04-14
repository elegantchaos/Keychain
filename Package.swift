// swift-tools-version:5.10

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
//  Created by Sam Deane on 06/04/2020.
//  All code (c) 2020 - present day, Elegant Chaos Limited.
// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

import PackageDescription

let package = Package(
  name: "Keychain",
  products: [
    .library(
      name: "Keychain",
      targets: ["Keychain"])
  ],
  dependencies: [],
  targets: [
    .target(
      name: "Keychain",
      dependencies: []),
    .testTarget(
      name: "KeychainTests",
      dependencies: ["Keychain"]),
  ]
)

#if swift(>=6.2)
  // this is a tool dependency, just used to refresh the CI workflow file
  package.dependencies.append(
    .package(
      url: "https://github.com/elegantchaos/ActionBuilderPlugin.git",
      from: "2.0.3"
    )
  )
#endif
