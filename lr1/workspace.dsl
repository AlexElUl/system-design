workspace {

    model {
        user = person "Пользователь" {
            description "Пользователь, использующий мессенджер для общения в чатах и отправки сообщений."
        }

        system = softwareSystem "Мессенджер" {
            description "Система мессенджера для общения пользователей через групповые и PtP чаты."


            
            webApp = container "Веб-приложение" {
                description "Веб-приложение для доступа к функционалу мессенджера."
                technology "React, Node.js"
            }

            mobileApp = container "Мобильное приложение" {
                description "Мобильное приложение для доступа к функционалу мессенджера."
                technology "React Native, Node.js"
            }

            apiServer = container "API-сервер" {
                description "API-сервер для обработки запросов и логики работы чатов."
                technology "Java, Spring Boot, REST"
            }

            database = container "База данных" {
                description "Реляционная база данных для хранения данных пользователей, сообщений и чатов."
                technology "PostgreSQL"
            }

            messageQueue = container "Месседж-очередь" {
                description "Механизм для асинхронной обработки сообщений и уведомлений."
                technology "RabbitMQ"
            }

            user -> apiServer "Отправляет запросы через REST API"
            mobileApp -> apiServer "Отправляет запросы через REST API"
            webApp -> apiServer "Отправляет запросы через REST API"
            apiServer -> database "Читает и записывает данные"
            apiServer -> messageQueue "Публикует сообщения для асинхронной обработки"
        }

        groupChat = softwareSystem "Групповой чат" {
            description "Групповой чат, состоящий из нескольких пользователей."
        }

        ptpChat = softwareSystem "PtP чат" {
            description "Чат между двумя пользователями (личные сообщения)."
        }

            user -> webApp "Использует через браузер"
            user -> mobileApp "Использует через мобильное приложение"

    }

    views {
        systemContext system {
            include *
            autolayout lr
        }

        container system {
            include *
            autolayout lr
        }

        dynamic system "uc01" "Отправка PtP сообщения" {
            description "Отправка PtP сообщения."
                user -> apiServer "Отправляет запрос на отправку PtP сообщения"
                apiServer -> database "Сохраняет сообщение в базе данных"
                apiServer -> messageQueue "Публикует уведомление о новом сообщении"          
        }
        theme default
    }
}
