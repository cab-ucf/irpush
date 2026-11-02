// swift-tools-version:5.10
// Build Irpush.xcframework first: `make ios` (macOS + Xcode).
import PackageDescription

let package = Package(
    name: "Irpush",
    platforms: [.iOS(.v15)],
    products: [.library(name: "Irpush", targets: ["Irpush"])],
    targets: [
        .binaryTarget(name: "IrpushC", path: "Irpush.xcframework"),
        .target(name: "Irpush", dependencies: ["IrpushC"], path: "ios/Sources/Irpush",
                linkerSettings: [.linkedFramework("Security"), .linkedFramework("SystemConfiguration"), .linkedLibrary("resolv")]),
    ]
)
