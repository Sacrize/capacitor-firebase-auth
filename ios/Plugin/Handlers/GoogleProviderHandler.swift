import Foundation
import Capacitor
import FirebaseCore
import FirebaseAuth
import GoogleSignIn


class GoogleProviderHandler: NSObject, ProviderHandler {

    var plugin: CapacitorFirebaseAuth? = nil
    var configuration: GIDConfiguration? = nil
    var scopes: [String] = []

    func initialize(plugin: CapacitorFirebaseAuth) {
        self.plugin = plugin
        print("Initializing Google Provider Handler")

        guard let clientId = FirebaseApp.app()?.options.clientID else {
            plugin.handleError(message: "There is no clientId from FirebaseApp")
            return
        }

        let propertiesMap = plugin.getConfigValue("properties") as? [String:Any] ?? [:]
        let permissions = plugin.getConfigValue("permissions") as? [String:Any] ?? [:]

        let googleProperties = propertiesMap["google"] as? [String:Any] ?? [:]

        let serverClientID = googleProperties["serverClientID"] as? String
        let hostedDomain = googleProperties["hostedDomain"] as? String
        let openIDRealm = googleProperties["openIDRealm"] as? String

        self.configuration = GIDConfiguration(clientID: clientId,
                                              serverClientID: serverClientID,
                                              hostedDomain: hostedDomain,
                                              openIDRealm: openIDRealm)

        GIDSignIn.sharedInstance.configuration = self.configuration

        if let scopes = permissions["google"] as? [String], let presentingVC = plugin.bridge?.viewController {
            self.scopes = scopes
        }

        NotificationCenter.default.addObserver(self, selector: #selector(handleOpenUrl(_ :)),
                                               name: Notification.Name(Notification.Name.capacitorOpenURL.rawValue),
                                               object: nil)

        GIDSignIn.sharedInstance.disconnect { error in
            guard error == nil else { return }
            // Google Account disconnected from your app.
            // Perform clean-up actions, such as deleting data associated with the disconnected account.
            self.signOut()
        }
    }

    @objc func handleOpenUrl(_ notification: Notification) {
        guard let object = notification.object as? JSObject else {
            self.plugin?.handleError(message: "There is no object on handleOpenUrl")
            return
        }

        guard let url = object["url"] as? URL else {
            self.plugin?.handleError(message: "There is no url on handleOpenUrl")
            return
        }

        let handled = GIDSignIn.sharedInstance.handle(url)
        print("GIDSignIn Provider handled url: \(handled)")
    }

    func signIn(call: CAPPluginCall) {
        guard let presentingVC = self.plugin?.bridge?.viewController
        else { return }

        GIDSignIn.sharedInstance.signIn(withPresenting: presentingVC, hint: nil, additionalScopes: self.scopes) { [unowned self] result, error in
            if let error = error {
                self.plugin?.handleError(message: error.localizedDescription)
                return
            }
            guard let user = result?.user,
                  let idToken = user.idToken?.tokenString
            else {
                self.plugin?.handleError(message: "There is no authenticated user")
                return
            }

            let accessToken = user.accessToken.tokenString
            let serverAuthCode = result?.serverAuthCode

            let credential = GoogleAuthProvider.credential(withIDToken: idToken,
                                                           accessToken: accessToken)
            self.plugin?.handleAuthCredentials(credential: credential)
        }
    }

    func isAuthenticated() -> Bool {
        return GIDSignIn.sharedInstance.currentUser != nil
    }

    func fillResult(credential: AuthCredential?, data: PluginCallResultData) -> PluginCallResultData {
        guard let currentUser = GIDSignIn.sharedInstance.currentUser else {
            return data
        }

        var jsResult: PluginCallResultData = [:]
        data.forEach { (key, value) in
            jsResult[key] = value
        }

        jsResult["idToken"] = currentUser.idToken?.tokenString

        return jsResult
    }

    func signOut() {
        GIDSignIn.sharedInstance.signOut()
    }
}
