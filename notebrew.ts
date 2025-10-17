const hamburgerMenuBtn = document.getElementById("hamburger-menu-btn");
const hamburgerMenuIcon = document.getElementById("hamburger-menu-icon");
const sidePane = document.getElementById("side-pane");
const menuPane = document.getElementById("menu-pane");
const notMenuPane = document.getElementById("not-menu-pane");
console.log({hamburgerMenuBtn, hamburgerMenuIcon, sidePane, notMenuPane});
if (hamburgerMenuBtn && hamburgerMenuIcon && sidePane && notMenuPane) {
  console.log("got here! 1");
  hamburgerMenuBtn.addEventListener("click", function() {
    console.log("got here! 2");
    if (hamburgerMenuIcon.classList.contains("open")) {
      hamburgerMenuIcon.classList.remove("open");
      sidePane.classList.add("hidden");
    } else {
      hamburgerMenuIcon.classList.add("open");
      sidePane.classList.remove("hidden");
    }
  });
  notMenuPane.addEventListener("click", function() {
    if (hamburgerMenuIcon.classList.contains("open")) {
      hamburgerMenuIcon.classList.remove("open");
      sidePane.classList.add("hidden");
    }
  });
}
for (const dataClickEventStopPropagation of document.querySelectorAll("[data-click-event-stop-propagation]")) {
  dataClickEventStopPropagation.addEventListener("click", function(event) {
    event.stopPropagation();
  });
}
