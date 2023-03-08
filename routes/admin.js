const path = require("path");

const express = require("express");

const adminController = require("../controllers/admin");

const router = express.Router();

const isAuth = require("../middleware/is-auth");

const { body } = require("express-validator");

// /admin/add-product => GET
router.get("/add-product", isAuth, adminController.getAddProduct);

// /admin/products => GET
router.get("/products", isAuth, adminController.getProducts);

// /admin/add-product => POST
router.post(
  "/add-product",
  [
    body("title").trim().isString().isLength({ min: 3 }),
    body("imageUrl", "Enter a valid uri").trim(),
    body("price", "Enter numbers only").trim().isFloat(),
    body("description").trim().isLength({ min: 8, max: 200 }),
  ],
  isAuth,
  adminController.postAddProduct
);

router.get("/edit-product/:productId", isAuth, adminController.getEditProduct);

router.post(
  "/edit-product", 
  [
    body("title").trim().isString().isLength({ min: 3 }),
    body("imageUrl", "Enter a valid uri").trim().isURL(),
    body("price", "Enter numbers only").trim().isFloat(),
    body("description").trim().isLength({ min: 8, max: 200 }),
  ],
  isAuth,
  adminController.postEditProduct
);

router.delete("/product/:productId", isAuth, adminController.deleteProduct);

module.exports = router;
