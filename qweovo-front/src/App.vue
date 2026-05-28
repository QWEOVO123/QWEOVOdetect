<template>
  <router-view />
</template>

<style>
*,
*::before,
*::after {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

html {
  background: #f4f8f6;
}

body {
  min-width: 320px;
  min-height: 100vh;
  font-family: Inter, 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', Arial, sans-serif;
  background: #f4f8f6;
  color: #18231f;
  text-rendering: optimizeLegibility;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

button,
input {
  font: inherit;
}

button {
  letter-spacing: 0;
}
</style>
