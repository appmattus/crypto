//
// Copyright 2021 Appmattus Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

import Foundation
import Combine
import shared

public extension Kotlinx_coroutines_coreFlow {
    func asPublisher<T: AnyObject>() -> AnyPublisher<T, Never> {
        (FlowPublisher(flow: self) as FlowPublisher<T>).eraseToAnyPublisher()
    }
}

private struct FlowPublisher<T: Any>: Publisher {
    public typealias Output = T
    public typealias Failure = Never

    private let flow: Kotlinx_coroutines_coreFlow

    public init(flow: Kotlinx_coroutines_coreFlow) {
        self.flow = flow
    }

    public func receive<S: Subscriber>(subscriber: S) where S.Input == T, S.Failure == Failure {
        let subscription = FlowSubscription(flow: flow, subscriber: subscriber)
        subscriber.receive(subscription: subscription)
    }

    final class FlowSubscription<S: Subscriber>: Subscription where S.Input == T, S.Failure == Failure {
        private var subscriber: S?
        private var job: Kotlinx_coroutines_coreJob?

        private let flow: Kotlinx_coroutines_coreFlow

        init(flow: Kotlinx_coroutines_coreFlow, subscriber: S) {
            self.flow = flow
            self.subscriber = subscriber

            job = SubscribeKt.subscribe(
                    flow,
                    onEach: { position in if let position = position as? T { _ = subscriber.receive(position) }},
                    onComplete: { subscriber.receive(completion: .finished) },
                    onThrow: { error in debugPrint(error) }
            )
        }

        func cancel() {
            subscriber = nil
            job?.cancel(cause: nil)
        }

        func request(_ demand: Subscribers.Demand) {
        }
    }
}
