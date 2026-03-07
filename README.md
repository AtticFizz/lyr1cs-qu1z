# Install
### Install dependencies
```
npm installl
```
### Setup Env variables
```
cp .env.example .env
```
### DB setup
```
npx prisma generate
npx prisma migrate dev --name init
```
### Run dev server
```
npm run dev
```