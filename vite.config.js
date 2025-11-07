import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Установка базового пути для GitHub Pages.
// Это необходимо, так как приложение размещено в подпапке /log-parser-app/
export default defineConfig({
  // Замените '/log-parser-app/' на имя вашего репозитория, если оно другое.
  base: '/log-parser-app/', 
  plugins: [react()],
  // Vite 7.x uses 'optimizeDeps' for dependencies
  optimizeDeps: {
    include: ['react', 'react-dom'],
  }
}
