//import { Controller } from "@hotwired/stimulus"

//export default class extends Controller {
//  connect() {
//    if (this.element.dataset.autostart === "true") {
//      this.startAnalysis()
//    }
//  }

//  startAnalysis() {
//    const extensionId = this.element.dataset.extensionId
//    fetch(`/welcome?id=${extensionId}&analyze=true`, {
//      headers: {
//        "Accept": "text/vnd.turbo-stream.html"
//      }
//    })
//  }
//} 